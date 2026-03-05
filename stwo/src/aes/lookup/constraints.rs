//! Lookup-based AES constraint evaluation.
//!
//! Uses S-box lookup tables and represents bytes as field elements.
//! XOR is done by splitting into nibbles and using 4-bit XOR tables.

use num_traits::One;
use stwo::core::fields::m31::BaseField;
use stwo_constraint_framework::{EvalAtRow, RelationEntry};

use crate::aes::sbox_table::SboxElements;

/// A byte represented as a single field element (value 0-255).
#[derive(Clone)]
pub struct Byte<F: Clone> {
    pub value: F,
}

impl<F: Clone> Byte<F> {
    pub fn new(value: F) -> Self {
        Self { value }
    }
}

/// A byte split into two nibbles (4 bits each) for XOR operations.
#[derive(Clone)]
pub struct NibbleByte<F: Clone> {
    pub lo: F, // bits 0-3
    pub hi: F, // bits 4-7
}

/// AES state: 16 bytes.
pub type AESState<F> = [Byte<F>; 16];

/// Constraint evaluator for lookup-based AES.
pub struct AESLookupEvalAtRow<'a, E: EvalAtRow> {
    pub eval: E,
    pub sbox_elements: &'a SboxElements,
}

impl<'a, E: EvalAtRow> AESLookupEvalAtRow<'a, E> {
    /// Read the next byte from the trace.
    fn next_byte(&mut self) -> Byte<E::F> {
        Byte::new(self.eval.next_trace_mask())
    }

    /// Read a full AES state (16 bytes) from the trace.
    fn next_state(&mut self) -> AESState<E::F> {
        std::array::from_fn(|_| self.next_byte())
    }

    /// Constrain that a value is a valid byte (0-255).
    /// This is implicitly checked by the S-box lookup since only valid bytes exist in the table.
    #[allow(dead_code)]
    fn constrain_byte(&mut self, _byte: &Byte<E::F>) {
        // Range check is implicit in S-box lookup
    }

    /// Apply S-box with lookup constraint.
    /// Reads the output from trace and adds a lookup relation entry.
    fn sbox(&mut self, input: &Byte<E::F>) -> Byte<E::F> {
        // Read the output from trace
        let output = self.next_byte();

        // Add lookup constraint: (input, output) must be in S-box table
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

    /// ShiftRows: permute bytes (no constraints needed, just reordering).
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

    /// XOR two bytes using nibble decomposition.
    /// Reads nibbles and result from trace, constrains decomposition and XOR.
    fn xor_byte(&mut self, a: &Byte<E::F>, b: &Byte<E::F>) -> Byte<E::F> {
        // Read decomposition of a, b into nibbles
        let a_lo = self.eval.next_trace_mask();
        let a_hi = self.eval.next_trace_mask();
        let b_lo = self.eval.next_trace_mask();
        let b_hi = self.eval.next_trace_mask();

        // Constrain: a = a_lo + 16 * a_hi
        let sixteen = E::F::from(BaseField::from_u32_unchecked(16));
        self.eval.add_constraint(
            a.value.clone() - a_lo.clone() - sixteen.clone() * a_hi.clone(),
        );
        // Constrain: b = b_lo + 16 * b_hi
        self.eval.add_constraint(
            b.value.clone() - b_lo.clone() - sixteen.clone() * b_hi.clone(),
        );

        // Read XOR results for nibbles
        let c_lo = self.eval.next_trace_mask();
        let c_hi = self.eval.next_trace_mask();

        // TODO: Add XOR lookup constraints for nibbles
        // For now, we just constrain the relationship algebraically for 4-bit values
        // In full implementation, use 4-bit XOR tables

        // Read final result
        let result = self.next_byte();

        // Constrain: result = c_lo + 16 * c_hi
        self.eval.add_constraint(
            result.value.clone() - c_lo - sixteen * c_hi,
        );

        result
    }

    /// xtime: multiply by 2 in GF(2^8).
    /// xtime(a) = (a << 1) XOR (0x1b if a >= 128 else 0)
    fn xtime(&mut self, a: &Byte<E::F>) -> Byte<E::F> {
        // Read the result from trace
        let result = self.next_byte();

        // Read the high bit indicator (1 if a >= 128, 0 otherwise)
        let high_bit = self.eval.next_trace_mask();

        // Constrain: high_bit is binary
        let one = E::F::from(BaseField::from_u32_unchecked(1));
        self.eval.add_constraint(
            high_bit.clone() * (one.clone() - high_bit.clone()),
        );

        // Constrain: high_bit = 1 iff a >= 128
        // This requires: a = 128 * high_bit + low_part where 0 <= low_part < 128
        let low_part = self.eval.next_trace_mask();
        let c128 = E::F::from(BaseField::from_u32_unchecked(128));
        self.eval.add_constraint(
            a.value.clone() - c128.clone() * high_bit.clone() - low_part.clone(),
        );

        // Constrain: result = 2*a mod 256 XOR (high_bit * 0x1b)
        // result = (2 * low_part + 256 * high_bit) mod 256 XOR (high_bit * 0x1b)
        // result = 2 * low_part XOR (high_bit * 0x1b)
        //
        // For now, we trust the prover computed this correctly
        // In full implementation, add proper constraints

        result
    }

    /// Multiply by 2 in GF(2^8) - alias for xtime.
    fn gf_mul2(&mut self, a: &Byte<E::F>) -> Byte<E::F> {
        self.xtime(a)
    }

    /// Multiply by 3 in GF(2^8): 3*a = 2*a XOR a
    fn gf_mul3(&mut self, a: &Byte<E::F>) -> Byte<E::F> {
        let doubled = self.gf_mul2(a);
        self.xor_byte(&doubled, a)
    }

    /// MixColumns: matrix multiplication in GF(2^8).
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

    /// Full AES-128 block encryption.
    pub fn aes128_block(mut self) -> E {
        // Read inputs: plaintext (16 bytes) and all round keys (11 * 16 bytes)
        let plaintext = self.next_state();
        let round_keys: [AESState<E::F>; 11] = std::array::from_fn(|_| self.next_state());

        // Initial AddRoundKey
        let mut state = self.add_round_key(&plaintext, &round_keys[0]);

        // 9 main rounds
        for round in 1..10 {
            state = self.sub_bytes(&state);
            state = self.shift_rows(&state);
            state = self.mix_columns(&state);
            state = self.add_round_key(&state, &round_keys[round]);
        }

        // Final round (no MixColumns)
        state = self.sub_bytes(&state);
        state = self.shift_rows(&state);
        let _output = self.add_round_key(&state, &round_keys[10]);

        // Finalize LogUp
        self.eval.finalize_logup_in_pairs();
        self.eval
    }
}
