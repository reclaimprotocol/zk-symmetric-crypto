//! Bitwise AES constraints.
//!
//! Represents bytes as 8 individual bits and implements GF(2^8) arithmetic
//! using algebraic constraints.

use stwo::core::fields::m31::BaseField;
use stwo_constraint_framework::EvalAtRow;

/// A byte represented as 8 bits (LSB to MSB).
#[derive(Clone)]
pub struct BitByte<F: Clone> {
    pub bits: [F; 8],
}

impl<F: Clone> BitByte<F> {
    pub fn new(bits: [F; 8]) -> Self {
        Self { bits }
    }
}

/// AES state: 16 bytes = 128 bits.
pub type AESState<F> = [BitByte<F>; 16];

/// Constraint evaluator for bitwise AES.
pub struct AESBitwiseEvalAtRow<E: EvalAtRow> {
    pub eval: E,
}

impl<E: EvalAtRow> AESBitwiseEvalAtRow<E> {
    /// Read the next bit from the trace.
    fn next_bit(&mut self) -> E::F {
        self.eval.next_trace_mask()
    }

    /// Read the next byte (8 bits) from the trace.
    fn next_byte(&mut self) -> BitByte<E::F> {
        BitByte::new(std::array::from_fn(|_| self.next_bit()))
    }

    /// Read a full AES state (16 bytes = 128 bits) from the trace.
    fn next_state(&mut self) -> AESState<E::F> {
        std::array::from_fn(|_| self.next_byte())
    }

    /// Constrain a value to be binary (0 or 1).
    fn constrain_bit(&mut self, bit: E::F) {
        // bit * (1 - bit) = 0
        let one = E::F::from(BaseField::from_u32_unchecked(1));
        self.eval.add_constraint(bit.clone() * (one - bit));
    }

    /// Constrain all bits in a byte to be binary.
    fn constrain_byte_bits(&mut self, byte: &BitByte<E::F>) {
        for bit in &byte.bits {
            self.constrain_bit(bit.clone());
        }
    }

    /// XOR two bits: result = a + b - 2*a*b
    fn xor_bit(&mut self, a: E::F, b: E::F) -> E::F {
        let two = E::F::from(BaseField::from_u32_unchecked(2));
        let result = self.next_bit();
        self.eval.add_constraint(
            result.clone() - a.clone() - b.clone() + two * a * b,
        );
        result
    }

    /// XOR two bytes.
    fn xor_byte(&mut self, a: &BitByte<E::F>, b: &BitByte<E::F>) -> BitByte<E::F> {
        BitByte::new(std::array::from_fn(|i| {
            self.xor_bit(a.bits[i].clone(), b.bits[i].clone())
        }))
    }

    /// AND two bits: result = a * b
    fn and_bit(&mut self, a: E::F, b: E::F) -> E::F {
        let result = self.next_bit();
        self.eval.add_constraint(result.clone() - a * b);
        result
    }

    /// GF(2^8) multiplication by x (xtime).
    /// xtime(a) = a << 1 XOR (0x1b if a[7] else 0)
    /// = (a[0..7] << 1) XOR (a[7] * 0x1b)
    fn xtime(&mut self, a: &BitByte<E::F>) -> BitByte<E::F> {
        // Shifted: [0, a0, a1, a2, a3, a4, a5, a6]

        // 0x1b = 0b00011011 = bits [0,1,3,4] set
        // Conditional XOR with 0x1b based on a[7]
        let high_bit = a.bits[7].clone();

        // Result bits:
        // result[0] = 0 XOR (a7 * 1) = a7
        // result[1] = a0 XOR (a7 * 1) = a0 XOR a7
        // result[2] = a1 XOR (a7 * 0) = a1
        // result[3] = a2 XOR (a7 * 1) = a2 XOR a7
        // result[4] = a3 XOR (a7 * 1) = a3 XOR a7
        // result[5] = a4 XOR (a7 * 0) = a4
        // result[6] = a5 XOR (a7 * 0) = a5
        // result[7] = a6 XOR (a7 * 0) = a6

        let result_bits: [E::F; 8] = [
            high_bit.clone(), // bit 0: a7
            self.xor_bit(a.bits[0].clone(), high_bit.clone()), // bit 1: a0 XOR a7
            a.bits[1].clone(), // bit 2: a1
            self.xor_bit(a.bits[2].clone(), high_bit.clone()), // bit 3: a2 XOR a7
            self.xor_bit(a.bits[3].clone(), high_bit.clone()), // bit 4: a3 XOR a7
            a.bits[4].clone(), // bit 5: a4
            a.bits[5].clone(), // bit 6: a5
            a.bits[6].clone(), // bit 7: a6
        ];

        BitByte::new(result_bits)
    }

    /// GF(2^8) multiplication of two bytes.
    /// Uses the standard "peasant's algorithm" with xtime.
    fn gf_mul(&mut self, a: &BitByte<E::F>, b: &BitByte<E::F>) -> BitByte<E::F> {
        let zero = E::F::from(BaseField::from_u32_unchecked(0));
        let zero_byte = BitByte::new(std::array::from_fn(|_| zero.clone()));

        // result = 0
        // for i in 0..8:
        //   if b[i]: result ^= a
        //   a = xtime(a)

        let mut result = zero_byte;
        let mut a_shifted = a.clone();

        for i in 0..8 {
            // Conditional XOR: if b[i] then result ^= a_shifted
            // new_result[j] = result[j] XOR (b[i] AND a_shifted[j])
            let b_bit = b.bits[i].clone();
            let new_result_bits: [E::F; 8] = std::array::from_fn(|j| {
                let term = self.and_bit(b_bit.clone(), a_shifted.bits[j].clone());
                self.xor_bit(result.bits[j].clone(), term)
            });
            result = BitByte::new(new_result_bits);

            // a_shifted = xtime(a_shifted) for next iteration
            if i < 7 {
                a_shifted = self.xtime(&a_shifted);
            }
        }

        result
    }

    /// Compute GF(2^8) inverse using x^254 = x^(-1).
    /// Uses addition chain: x^2, x^3, x^6, x^12, x^14, x^15, x^30, x^60, x^120, x^126, x^127, x^254
    fn gf_inv(&mut self, x: &BitByte<E::F>) -> BitByte<E::F> {
        let x2 = self.gf_mul(x, x);
        let x3 = self.gf_mul(&x2, x);
        let x6 = self.gf_mul(&x3, &x3);
        let x12 = self.gf_mul(&x6, &x6);
        let x14 = self.gf_mul(&x12, &x2);
        let x15 = self.gf_mul(&x14, x);
        let x30 = self.gf_mul(&x15, &x15);
        let x60 = self.gf_mul(&x30, &x30);
        let x120 = self.gf_mul(&x60, &x60);
        let x126 = self.gf_mul(&x120, &x6);
        let x127 = self.gf_mul(&x126, x);
        let x254 = self.gf_mul(&x127, &x127);

        x254
    }

    /// Apply the affine transformation for S-box.
    /// b'[i] = b[i] XOR b[(i+4)%8] XOR b[(i+5)%8] XOR b[(i+6)%8] XOR b[(i+7)%8] XOR c[i]
    /// where c = 0x63 = 0b01100011
    fn affine_transform(&mut self, inv: &BitByte<E::F>) -> BitByte<E::F> {
        // c = 0x63 = bits 0,1,5,6 set
        let c_bits: [u32; 8] = [1, 1, 0, 0, 0, 1, 1, 0];

        let mut result_bits: [E::F; 8] = std::array::from_fn(|_| {
            E::F::from(BaseField::from_u32_unchecked(0))
        });

        for i in 0..8 {
            // XOR five rotations of inv
            let mut acc = inv.bits[i].clone();
            acc = self.xor_bit(acc, inv.bits[(i + 4) % 8].clone());
            acc = self.xor_bit(acc, inv.bits[(i + 5) % 8].clone());
            acc = self.xor_bit(acc, inv.bits[(i + 6) % 8].clone());
            acc = self.xor_bit(acc, inv.bits[(i + 7) % 8].clone());

            // XOR with constant bit
            if c_bits[i] == 1 {
                let one = E::F::from(BaseField::from_u32_unchecked(1));
                acc = self.xor_bit(acc, one);
            }

            result_bits[i] = acc;
        }

        BitByte::new(result_bits)
    }

    /// Compute S-box: inverse + affine transform.
    /// Note: For input 0, the inverse is defined as 0.
    fn sbox(&mut self, x: &BitByte<E::F>) -> BitByte<E::F> {
        // Check if x is zero
        // x_is_nonzero = x[0] OR x[1] OR ... OR x[7]
        // For zero input, we need special handling

        // Compute inverse (this gives 0 for input 0, which is correct for the
        // multiplication but we need to handle it specially)
        let inv = self.gf_inv(x);

        // Apply affine transform
        // For x=0: inv=0, affine(0) = 0x63 (which is correct S-box output)
        self.affine_transform(&inv)
    }

    /// SubBytes: apply S-box to all 16 bytes.
    fn sub_bytes(&mut self, state: &AESState<E::F>) -> AESState<E::F> {
        std::array::from_fn(|i| self.sbox(&state[i]))
    }

    /// ShiftRows: permute bytes (no constraints needed, just reordering).
    fn shift_rows(&self, state: &AESState<E::F>) -> AESState<E::F> {
        // AES state layout (column-major):
        // [ 0  4  8 12 ]
        // [ 1  5  9 13 ]
        // [ 2  6 10 14 ]
        // [ 3  7 11 15 ]
        //
        // After ShiftRows:
        // [ 0  4  8 12 ]  (row 0: no shift)
        // [ 5  9 13  1 ]  (row 1: shift left 1)
        // [10 14  2  6 ]  (row 2: shift left 2)
        // [15  3  7 11 ]  (row 3: shift left 3)

        [
            state[0].clone(),  // 0
            state[5].clone(),  // 1 <- 5
            state[10].clone(), // 2 <- 10
            state[15].clone(), // 3 <- 15
            state[4].clone(),  // 4
            state[9].clone(),  // 5 <- 9
            state[14].clone(), // 6 <- 14
            state[3].clone(),  // 7 <- 3
            state[8].clone(),  // 8
            state[13].clone(), // 9 <- 13
            state[2].clone(),  // 10 <- 2
            state[7].clone(),  // 11 <- 7
            state[12].clone(), // 12
            state[1].clone(),  // 13 <- 1
            state[6].clone(),  // 14 <- 6
            state[11].clone(), // 15 <- 11
        ]
    }

    /// MixColumns: matrix multiplication in GF(2^8).
    /// Each column [s0, s1, s2, s3] transforms to:
    /// [2*s0 + 3*s1 + s2 + s3]
    /// [s0 + 2*s1 + 3*s2 + s3]
    /// [s0 + s1 + 2*s2 + 3*s3]
    /// [3*s0 + s1 + s2 + 2*s3]
    fn mix_columns(&mut self, state: &AESState<E::F>) -> AESState<E::F> {
        let mut result: [BitByte<E::F>; 16] = std::array::from_fn(|_| {
            BitByte::new(std::array::from_fn(|_| {
                E::F::from(BaseField::from_u32_unchecked(0))
            }))
        });

        // Constant 2 and 3 in GF(2^8)
        let two = self.const_byte(0x02);
        let three = self.const_byte(0x03);

        for col in 0..4 {
            let i = col * 4;
            let s0 = &state[i];
            let s1 = &state[i + 1];
            let s2 = &state[i + 2];
            let s3 = &state[i + 3];

            // r0 = 2*s0 + 3*s1 + s2 + s3
            let t0 = self.gf_mul(&two, s0);
            let t1 = self.gf_mul(&three, s1);
            let t2 = self.xor_byte(&t0, &t1);
            let t3 = self.xor_byte(&t2, s2);
            result[i] = self.xor_byte(&t3, s3);

            // r1 = s0 + 2*s1 + 3*s2 + s3
            let t0 = self.gf_mul(&two, s1);
            let t1 = self.gf_mul(&three, s2);
            let t2 = self.xor_byte(s0, &t0);
            let t3 = self.xor_byte(&t2, &t1);
            result[i + 1] = self.xor_byte(&t3, s3);

            // r2 = s0 + s1 + 2*s2 + 3*s3
            let t0 = self.gf_mul(&two, s2);
            let t1 = self.gf_mul(&three, s3);
            let t2 = self.xor_byte(s0, s1);
            let t3 = self.xor_byte(&t2, &t0);
            result[i + 2] = self.xor_byte(&t3, &t1);

            // r3 = 3*s0 + s1 + s2 + 2*s3
            let t0 = self.gf_mul(&three, s0);
            let t1 = self.gf_mul(&two, s3);
            let t2 = self.xor_byte(&t0, s1);
            let t3 = self.xor_byte(&t2, s2);
            result[i + 3] = self.xor_byte(&t3, &t1);
        }

        result
    }

    /// Create a constant byte.
    fn const_byte(&self, value: u8) -> BitByte<E::F> {
        BitByte::new(std::array::from_fn(|i| {
            let bit = (value >> i) & 1;
            E::F::from(BaseField::from_u32_unchecked(bit as u32))
        }))
    }

    /// AddRoundKey: XOR state with round key.
    fn add_round_key(&mut self, state: &AESState<E::F>, round_key: &AESState<E::F>) -> AESState<E::F> {
        std::array::from_fn(|i| self.xor_byte(&state[i], &round_key[i]))
    }

    /// Full AES-128 block encryption.
    pub fn aes128_block(mut self) -> E {
        // Read inputs: plaintext (16 bytes) and key (16 bytes)
        // We'll read expanded round keys for simplicity
        let plaintext = self.next_state();
        let round_keys: [AESState<E::F>; 11] = std::array::from_fn(|_| self.next_state());

        // Constrain input bits
        for byte in &plaintext {
            self.constrain_byte_bits(byte);
        }
        for rk in &round_keys {
            for byte in rk {
                self.constrain_byte_bits(byte);
            }
        }

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

        self.eval
    }
}
