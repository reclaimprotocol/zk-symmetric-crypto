//! AES-CTR mode constraint evaluation.
//!
//! CTR mode: ciphertext[i] = plaintext[i] XOR AES(key, nonce || counter[i])
//!
//! The circuit proves:
//! 1. Counter block construction: nonce (12 bytes) || counter (4 bytes)
//! 2. AES encryption of counter block
//! 3. XOR of AES output with plaintext to produce ciphertext

use num_traits::One;
use stwo::core::fields::m31::BaseField;
use stwo_constraint_framework::{EvalAtRow, RelationEntry};

use crate::aes::sbox_table::SboxElements;
use crate::aes::AesKeySize;

use super::constraints::{AESState, Byte};

/// Constraint evaluator for AES-CTR mode.
pub struct AESCtrEvalAtRow<'a, E: EvalAtRow> {
    pub eval: E,
    pub sbox_elements: &'a SboxElements,
    pub key_size: AesKeySize,
}

impl<'a, E: EvalAtRow> AESCtrEvalAtRow<'a, E> {
    fn next_byte(&mut self) -> Byte<E::F> {
        Byte::new(self.eval.next_trace_mask())
    }

    fn next_state(&mut self) -> AESState<E::F> {
        std::array::from_fn(|_| self.next_byte())
    }

    fn sbox(&mut self, input: &Byte<E::F>) -> Byte<E::F> {
        let output = self.next_byte();

        self.eval.add_to_relation(RelationEntry::new(
            self.sbox_elements,
            E::EF::one(),
            &[input.value.clone(), output.value.clone()],
        ));

        output
    }

    fn sub_bytes(&mut self, state: &AESState<E::F>) -> AESState<E::F> {
        std::array::from_fn(|i| self.sbox(&state[i]))
    }

    fn shift_rows(&self, state: &AESState<E::F>) -> AESState<E::F> {
        [
            state[0].clone(),
            state[5].clone(),
            state[10].clone(),
            state[15].clone(),
            state[4].clone(),
            state[9].clone(),
            state[14].clone(),
            state[3].clone(),
            state[8].clone(),
            state[13].clone(),
            state[2].clone(),
            state[7].clone(),
            state[12].clone(),
            state[1].clone(),
            state[6].clone(),
            state[11].clone(),
        ]
    }

    fn xor_byte(&mut self, a: &Byte<E::F>, b: &Byte<E::F>) -> Byte<E::F> {
        let a_lo = self.eval.next_trace_mask();
        let a_hi = self.eval.next_trace_mask();
        let b_lo = self.eval.next_trace_mask();
        let b_hi = self.eval.next_trace_mask();

        let sixteen = E::F::from(BaseField::from_u32_unchecked(16));
        self.eval
            .add_constraint(a.value.clone() - a_lo.clone() - sixteen.clone() * a_hi.clone());
        self.eval
            .add_constraint(b.value.clone() - b_lo.clone() - sixteen.clone() * b_hi.clone());

        let c_lo = self.eval.next_trace_mask();
        let c_hi = self.eval.next_trace_mask();

        let result = self.next_byte();

        self.eval
            .add_constraint(result.value.clone() - c_lo - sixteen * c_hi);

        result
    }

    fn xtime(&mut self, a: &Byte<E::F>) -> Byte<E::F> {
        let result = self.next_byte();
        let high_bit = self.eval.next_trace_mask();

        let one = E::F::from(BaseField::from_u32_unchecked(1));
        self.eval
            .add_constraint(high_bit.clone() * (one - high_bit.clone()));

        let low_part = self.eval.next_trace_mask();
        let c128 = E::F::from(BaseField::from_u32_unchecked(128));
        self.eval
            .add_constraint(a.value.clone() - c128 * high_bit - low_part);

        result
    }

    fn gf_mul2(&mut self, a: &Byte<E::F>) -> Byte<E::F> {
        self.xtime(a)
    }

    fn gf_mul3(&mut self, a: &Byte<E::F>) -> Byte<E::F> {
        let doubled = self.gf_mul2(a);
        self.xor_byte(&doubled, a)
    }

    fn mix_columns(&mut self, state: &AESState<E::F>) -> AESState<E::F> {
        let mut result: [Byte<E::F>; 16] =
            std::array::from_fn(|_| Byte::new(E::F::from(BaseField::from_u32_unchecked(0))));

        for col in 0..4 {
            let i = col * 4;
            let s0 = &state[i];
            let s1 = &state[i + 1];
            let s2 = &state[i + 2];
            let s3 = &state[i + 3];

            let t0 = self.gf_mul2(s0);
            let t1 = self.gf_mul3(s1);
            let t2 = self.xor_byte(&t0, &t1);
            let t3 = self.xor_byte(&t2, s2);
            result[i] = self.xor_byte(&t3, s3);

            let t0 = self.gf_mul2(s1);
            let t1 = self.gf_mul3(s2);
            let t2 = self.xor_byte(s0, &t0);
            let t3 = self.xor_byte(&t2, &t1);
            result[i + 1] = self.xor_byte(&t3, s3);

            let t0 = self.gf_mul2(s2);
            let t1 = self.gf_mul3(s3);
            let t2 = self.xor_byte(s0, s1);
            let t3 = self.xor_byte(&t2, &t0);
            result[i + 2] = self.xor_byte(&t3, &t1);

            let t0 = self.gf_mul3(s0);
            let t1 = self.gf_mul2(s3);
            let t2 = self.xor_byte(&t0, s1);
            let t3 = self.xor_byte(&t2, s2);
            result[i + 3] = self.xor_byte(&t3, &t1);
        }

        result
    }

    fn add_round_key(
        &mut self,
        state: &AESState<E::F>,
        round_key: &AESState<E::F>,
    ) -> AESState<E::F> {
        std::array::from_fn(|i| self.xor_byte(&state[i], &round_key[i]))
    }

    /// AES block encryption (parameterized by key size).
    fn aes_block(&mut self, counter_block: &AESState<E::F>, round_keys: &[AESState<E::F>]) -> AESState<E::F> {
        let num_rounds = self.key_size.num_rounds();

        // Initial AddRoundKey
        let mut state = self.add_round_key(counter_block, &round_keys[0]);

        // Main rounds (num_rounds - 1)
        for round in 1..num_rounds {
            state = self.sub_bytes(&state);
            state = self.shift_rows(&state);
            state = self.mix_columns(&state);
            state = self.add_round_key(&state, &round_keys[round]);
        }

        // Final round (no MixColumns)
        state = self.sub_bytes(&state);
        state = self.shift_rows(&state);
        self.add_round_key(&state, &round_keys[num_rounds])
    }

    /// CTR mode: encrypts one block.
    /// Inputs from trace:
    /// - nonce (12 bytes)
    /// - counter (4 bytes)
    /// - round_keys (11 or 15 states depending on key size)
    /// - plaintext (16 bytes)
    /// Outputs:
    /// - ciphertext (16 bytes)
    pub fn ctr_block(mut self) -> E {
        let num_round_keys = self.key_size.num_round_keys();

        // Read nonce (12 bytes) and counter (4 bytes) to form counter block
        let nonce: [Byte<E::F>; 12] = std::array::from_fn(|_| self.next_byte());
        let counter: [Byte<E::F>; 4] = std::array::from_fn(|_| self.next_byte());

        // Form counter block
        let counter_block: AESState<E::F> = std::array::from_fn(|i| {
            if i < 12 {
                nonce[i].clone()
            } else {
                counter[i - 12].clone()
            }
        });

        // Read round keys
        let round_keys: Vec<AESState<E::F>> = (0..num_round_keys)
            .map(|_| self.next_state())
            .collect();

        // Read plaintext - PUBLIC INPUT
        let plaintext = self.next_state();

        // Read ciphertext - PUBLIC INPUT (for verification)
        let expected_ciphertext = self.next_state();

        // AES encrypt counter block
        let keystream = self.aes_block(&counter_block, &round_keys);

        // XOR keystream with plaintext to get computed ciphertext
        let computed_ciphertext: AESState<E::F> = std::array::from_fn(|i| {
            self.xor_byte(&keystream[i], &plaintext[i])
        });

        // Constrain computed ciphertext == expected ciphertext
        for i in 0..16 {
            self.eval.add_constraint(
                computed_ciphertext[i].value.clone() - expected_ciphertext[i].value.clone(),
            );
        }

        self.eval.finalize_logup_in_pairs();
        self.eval
    }
}
