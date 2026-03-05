//! Lookup-based AES-256 constraint evaluation.
//!
//! Same as AES-128 but with 14 rounds instead of 10.

use num_traits::One;
use stwo::core::fields::m31::BaseField;
use stwo_constraint_framework::{EvalAtRow, RelationEntry};

use crate::aes::sbox_table::SboxElements;

use super::constraints::{AESState, Byte};

/// Constraint evaluator for lookup-based AES-256.
pub struct AES256LookupEvalAtRow<'a, E: EvalAtRow> {
    pub eval: E,
    pub sbox_elements: &'a SboxElements,
}

impl<'a, E: EvalAtRow> AES256LookupEvalAtRow<'a, E> {
    /// Read the next byte from the trace.
    fn next_byte(&mut self) -> Byte<E::F> {
        Byte::new(self.eval.next_trace_mask())
    }

    /// Read a full AES state (16 bytes) from the trace.
    fn next_state(&mut self) -> AESState<E::F> {
        std::array::from_fn(|_| self.next_byte())
    }

    /// Apply S-box with lookup constraint.
    fn sbox(&mut self, input: &Byte<E::F>) -> Byte<E::F> {
        let output = self.next_byte();

        self.eval.add_to_relation(RelationEntry::new(
            self.sbox_elements,
            E::EF::one(),
            &[input.value.clone(), output.value.clone()],
        ));

        output
    }

    /// SubBytes: apply S-box to all 16 bytes.
    fn sub_bytes(&mut self, state: &AESState<E::F>) -> AESState<E::F> {
        std::array::from_fn(|i| self.sbox(&state[i]))
    }

    /// ShiftRows: permute bytes.
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

    /// XOR two bytes using bit decomposition.
    /// Reads bits and result from trace, constrains decomposition and XOR at bit level.
    fn xor_byte(&mut self, a: &Byte<E::F>, b: &Byte<E::F>) -> Byte<E::F> {
        let one = E::F::from(BaseField::from_u32_unchecked(1));
        let two = E::F::from(BaseField::from_u32_unchecked(2));

        // Read bit decomposition of a (8 bits)
        let a_bits: [E::F; 8] = std::array::from_fn(|_| {
            let bit = self.eval.next_trace_mask();
            self.eval
                .add_constraint(bit.clone() * (one.clone() - bit.clone()));
            bit
        });

        // Read bit decomposition of b (8 bits)
        let b_bits: [E::F; 8] = std::array::from_fn(|_| {
            let bit = self.eval.next_trace_mask();
            self.eval
                .add_constraint(bit.clone() * (one.clone() - bit.clone()));
            bit
        });

        // Read bit decomposition of result (8 bits)
        let c_bits: [E::F; 8] = std::array::from_fn(|_| {
            let bit = self.eval.next_trace_mask();
            self.eval
                .add_constraint(bit.clone() * (one.clone() - bit.clone()));
            bit
        });

        // Constrain: a = sum of a_bits[i] * 2^i
        let mut a_sum = E::F::from(BaseField::from_u32_unchecked(0));
        let mut power = E::F::from(BaseField::from_u32_unchecked(1));
        for i in 0..8 {
            a_sum = a_sum + power.clone() * a_bits[i].clone();
            if i < 7 {
                power = power * two.clone();
            }
        }
        self.eval.add_constraint(a.value.clone() - a_sum);

        // Constrain: b = sum of b_bits[i] * 2^i
        let mut b_sum = E::F::from(BaseField::from_u32_unchecked(0));
        let mut power = E::F::from(BaseField::from_u32_unchecked(1));
        for i in 0..8 {
            b_sum = b_sum + power.clone() * b_bits[i].clone();
            if i < 7 {
                power = power * two.clone();
            }
        }
        self.eval.add_constraint(b.value.clone() - b_sum);

        // Constrain XOR at bit level: c[i] = a[i] + b[i] - 2*a[i]*b[i]
        for i in 0..8 {
            self.eval.add_constraint(
                c_bits[i].clone() - a_bits[i].clone() - b_bits[i].clone()
                    + two.clone() * a_bits[i].clone() * b_bits[i].clone(),
            );
        }

        // Read final result byte
        let result = self.next_byte();

        // Constrain: result = sum of c_bits[i] * 2^i
        let mut c_sum = E::F::from(BaseField::from_u32_unchecked(0));
        let mut power = E::F::from(BaseField::from_u32_unchecked(1));
        for i in 0..8 {
            c_sum = c_sum + power.clone() * c_bits[i].clone();
            if i < 7 {
                power = power * two.clone();
            }
        }
        self.eval.add_constraint(result.value.clone() - c_sum);

        result
    }

    /// xtime: multiply by 2 in GF(2^8).
    /// xtime(a) = (a << 1) XOR (0x1b if a >= 128 else 0)
    fn xtime(&mut self, a: &Byte<E::F>) -> Byte<E::F> {
        let one = E::F::from(BaseField::from_u32_unchecked(1));
        let two = E::F::from(BaseField::from_u32_unchecked(2));

        // Read bit decomposition of a (8 bits)
        let a_bits: [E::F; 8] = std::array::from_fn(|_| {
            let bit = self.eval.next_trace_mask();
            self.eval
                .add_constraint(bit.clone() * (one.clone() - bit.clone()));
            bit
        });

        // Constrain: a = sum of a_bits[i] * 2^i
        let mut a_sum = E::F::from(BaseField::from_u32_unchecked(0));
        let mut power = E::F::from(BaseField::from_u32_unchecked(1));
        for i in 0..8 {
            a_sum = a_sum + power.clone() * a_bits[i].clone();
            if i < 7 {
                power = power * two.clone();
            }
        }
        self.eval.add_constraint(a.value.clone() - a_sum);

        // Read bit decomposition of result (8 bits)
        let r_bits: [E::F; 8] = std::array::from_fn(|_| {
            let bit = self.eval.next_trace_mask();
            self.eval
                .add_constraint(bit.clone() * (one.clone() - bit.clone()));
            bit
        });

        // xtime at bit level: shifted[0]=0, shifted[i]=a[i-1] for i=1..7
        // If a[7]=1, XOR with 0x1b = 0b00011011
        let high_bit = a_bits[7].clone();

        // r[0] = a[7]
        self.eval.add_constraint(r_bits[0].clone() - high_bit.clone());

        // r[1] = a[0] XOR a[7]
        self.eval.add_constraint(
            r_bits[1].clone() - a_bits[0].clone() - high_bit.clone()
                + two.clone() * a_bits[0].clone() * high_bit.clone(),
        );

        // r[2] = a[1]
        self.eval.add_constraint(r_bits[2].clone() - a_bits[1].clone());

        // r[3] = a[2] XOR a[7]
        self.eval.add_constraint(
            r_bits[3].clone() - a_bits[2].clone() - high_bit.clone()
                + two.clone() * a_bits[2].clone() * high_bit.clone(),
        );

        // r[4] = a[3] XOR a[7]
        self.eval.add_constraint(
            r_bits[4].clone() - a_bits[3].clone() - high_bit.clone()
                + two.clone() * a_bits[3].clone() * high_bit.clone(),
        );

        // r[5] = a[4]
        self.eval.add_constraint(r_bits[5].clone() - a_bits[4].clone());

        // r[6] = a[5]
        self.eval.add_constraint(r_bits[6].clone() - a_bits[5].clone());

        // r[7] = a[6]
        self.eval.add_constraint(r_bits[7].clone() - a_bits[6].clone());

        // Read final result byte
        let result = self.next_byte();

        // Constrain: result = sum of r_bits[i] * 2^i
        let mut r_sum = E::F::from(BaseField::from_u32_unchecked(0));
        let mut power = E::F::from(BaseField::from_u32_unchecked(1));
        for i in 0..8 {
            r_sum = r_sum + power.clone() * r_bits[i].clone();
            if i < 7 {
                power = power * two.clone();
            }
        }
        self.eval.add_constraint(result.value.clone() - r_sum);

        result
    }

    /// Multiply by 2 in GF(2^8).
    fn gf_mul2(&mut self, a: &Byte<E::F>) -> Byte<E::F> {
        self.xtime(a)
    }

    /// Multiply by 3 in GF(2^8): 3*a = 2*a XOR a
    fn gf_mul3(&mut self, a: &Byte<E::F>) -> Byte<E::F> {
        let doubled = self.gf_mul2(a);
        self.xor_byte(&doubled, a)
    }

    /// MixColumns transformation.
    fn mix_columns(&mut self, state: &AESState<E::F>) -> AESState<E::F> {
        let mut result: [Byte<E::F>; 16] = std::array::from_fn(|_| {
            Byte::new(E::F::from(BaseField::from_u32_unchecked(0)))
        });

        for col in 0..4 {
            let i = col * 4;
            let s0 = &state[i];
            let s1 = &state[i + 1];
            let s2 = &state[i + 2];
            let s3 = &state[i + 3];

            // r0 = 2*s0 + 3*s1 + s2 + s3
            let t0 = self.gf_mul2(s0);
            let t1 = self.gf_mul3(s1);
            let t2 = self.xor_byte(&t0, &t1);
            let t3 = self.xor_byte(&t2, s2);
            result[i] = self.xor_byte(&t3, s3);

            // r1 = s0 + 2*s1 + 3*s2 + s3
            let t0 = self.gf_mul2(s1);
            let t1 = self.gf_mul3(s2);
            let t2 = self.xor_byte(s0, &t0);
            let t3 = self.xor_byte(&t2, &t1);
            result[i + 1] = self.xor_byte(&t3, s3);

            // r2 = s0 + s1 + 2*s2 + 3*s3
            let t0 = self.gf_mul2(s2);
            let t1 = self.gf_mul3(s3);
            let t2 = self.xor_byte(s0, s1);
            let t3 = self.xor_byte(&t2, &t0);
            result[i + 2] = self.xor_byte(&t3, &t1);

            // r3 = 3*s0 + s1 + s2 + 2*s3
            let t0 = self.gf_mul3(s0);
            let t1 = self.gf_mul2(s3);
            let t2 = self.xor_byte(&t0, s1);
            let t3 = self.xor_byte(&t2, s2);
            result[i + 3] = self.xor_byte(&t3, &t1);
        }

        result
    }

    /// AddRoundKey: XOR state with round key.
    fn add_round_key(&mut self, state: &AESState<E::F>, round_key: &AESState<E::F>) -> AESState<E::F> {
        std::array::from_fn(|i| self.xor_byte(&state[i], &round_key[i]))
    }

    /// Full AES-256 block encryption (14 rounds).
    pub fn aes256_block(mut self) -> E {
        // Read inputs: plaintext (16 bytes) and all round keys (15 * 16 bytes)
        let plaintext = self.next_state();
        let round_keys: [AESState<E::F>; 15] = std::array::from_fn(|_| self.next_state());

        // Initial AddRoundKey
        let mut state = self.add_round_key(&plaintext, &round_keys[0]);

        // 13 main rounds
        for round in 1..14 {
            state = self.sub_bytes(&state);
            state = self.shift_rows(&state);
            state = self.mix_columns(&state);
            state = self.add_round_key(&state, &round_keys[round]);
        }

        // Final round (no MixColumns)
        state = self.sub_bytes(&state);
        state = self.shift_rows(&state);
        let _output = self.add_round_key(&state, &round_keys[14]);

        self.eval.finalize_logup_in_pairs();
        self.eval
    }
}
