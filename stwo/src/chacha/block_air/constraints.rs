//! ChaCha20 full block constraint evaluation.
//!
//! A full block consists of:
//! - 10 double-rounds (each: 4 column QRs + 4 diagonal QRs)
//! - Final addition: output[i] = working_state[i] + initial_state[i]

use stwo::core::fields::m31::BaseField;
use stwo_constraint_framework::EvalAtRow;

use crate::chacha::constraints::ChaChaXorElements;
use crate::chacha::{Fu32, STATE_SIZE};

/// Inverse of 2^16 in M31, used for carry extraction.
const INV16: BaseField = BaseField::from_u32_unchecked(1 << 15);

/// Constraint evaluator for a ChaCha full block.
pub struct ChaChaBlockEvalAtRow<'a, E: EvalAtRow> {
    pub eval: E,
    pub xor_lookup_elements: &'a ChaChaXorElements,
}

impl<E: EvalAtRow> ChaChaBlockEvalAtRow<'_, E> {
    /// Evaluate constraints for a full ChaCha20 block.
    pub fn eval(mut self) -> E {
        // Read initial state (16 u32 values = 32 field elements)
        let initial: [Fu32<E::F>; STATE_SIZE] = std::array::from_fn(|_| self.next_u32());
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
            let _output = self.add2_u32(v[i].clone(), initial[i].clone());
        }

        self.eval.finalize_logup_in_pairs();
        self.eval
    }

    /// Read next u32 from trace (as two 16-bit field elements).
    fn next_u32(&mut self) -> Fu32<E::F> {
        let l = self.eval.next_trace_mask();
        let h = self.eval.next_trace_mask();
        Fu32 { l, h }
    }

    /// ChaCha quarter-round on indices a, b, c, d.
    fn quarter_round(&mut self, v: &mut [Fu32<E::F>; STATE_SIZE], a: usize, b: usize, c: usize, d: usize) {
        // a += b; d ^= a; d <<<= 16
        v[a] = self.add2_u32(v[a].clone(), v[b].clone());
        v[d] = self.xor_rotl16_u32(v[a].clone(), v[d].clone());

        // c += d; b ^= c; b <<<= 12
        v[c] = self.add2_u32(v[c].clone(), v[d].clone());
        v[b] = self.xor_rotl_u32(v[c].clone(), v[b].clone(), 12);

        // a += b; d ^= a; d <<<= 8
        v[a] = self.add2_u32(v[a].clone(), v[b].clone());
        v[d] = self.xor_rotl_u32(v[a].clone(), v[d].clone(), 8);

        // c += d; b ^= c; b <<<= 7
        v[c] = self.add2_u32(v[c].clone(), v[d].clone());
        v[b] = self.xor_rotl_u32(v[c].clone(), v[b].clone(), 7);
    }

    /// Add two u32s with carry constraint.
    fn add2_u32(&mut self, a: Fu32<E::F>, b: Fu32<E::F>) -> Fu32<E::F> {
        // Read result from trace
        let sl = self.eval.next_trace_mask();
        let sh = self.eval.next_trace_mask();

        // Constrain carry_l in {0, 1}
        let carry_l = (a.l.clone() + b.l.clone() - sl.clone()) * E::F::from(INV16);
        self.eval
            .add_constraint(carry_l.clone() * carry_l.clone() - carry_l.clone());

        // Constrain carry_h in {0, 1}
        let carry_h = (a.h + b.h + carry_l - sh.clone()) * E::F::from(INV16);
        self.eval
            .add_constraint(carry_h.clone() * carry_h.clone() - carry_h.clone());

        Fu32 { l: sl, h: sh }
    }

    /// XOR and left-rotate by 16 bits (swap halves after XOR).
    fn xor_rotl16_u32(&mut self, a: Fu32<E::F>, b: Fu32<E::F>) -> Fu32<E::F> {
        // Split each half at 8 bits for XOR lookups
        let (all, alh) = self.split(a.l.clone(), 8);
        let (ahl, ahh) = self.split(a.h.clone(), 8);
        let (bll, blh) = self.split(b.l.clone(), 8);
        let (bhl, bhh) = self.split(b.h.clone(), 8);

        // XOR the parts (8-bit width)
        let [xorll, xorhl] = self.xor2(8, [all, ahl], [bll, bhl]);
        let [xorlh, xorhh] = self.xor2(8, [alh, ahh], [blh, bhh]);

        // Reassemble with LEFT rotation by 16 (swap halves)
        Fu32 {
            l: xorhh * E::F::from(BaseField::from_u32_unchecked(1 << 8)) + xorhl,
            h: xorlh * E::F::from(BaseField::from_u32_unchecked(1 << 8)) + xorll,
        }
    }

    /// XOR and left-rotate by r bits (0 < r < 16).
    fn xor_rotl_u32(&mut self, a: Fu32<E::F>, b: Fu32<E::F>, r: u32) -> Fu32<E::F> {
        // Split at (16-r) to get: low (16-r bits) and high (r bits)
        let (all, alh) = self.split(a.l.clone(), 16 - r);
        let (ahl, ahh) = self.split(a.h.clone(), 16 - r);
        let (bll, blh) = self.split(b.l.clone(), 16 - r);
        let (bhl, bhh) = self.split(b.h.clone(), 16 - r);

        // XOR: low parts are (16-r) bits, high parts are r bits
        let [xorll, xorhl] = self.xor2(16 - r, [all, ahl], [bll, bhl]);
        let [xorlh, xorhh] = self.xor2(r, [alh, ahh], [blh, bhh]);

        // Reassemble with LEFT rotation by r
        let shift = E::F::from(BaseField::from_u32_unchecked(1 << r));
        Fu32 {
            l: xorll * shift.clone() + xorhh,
            h: xorhl * shift + xorlh,
        }
    }

    /// Split a field element at position r.
    /// Returns (low r bits, high (16-r) bits).
    fn split(&mut self, a: E::F, r: u32) -> (E::F, E::F) {
        let h = self.eval.next_trace_mask(); // High part from trace
        let l = a - h.clone() * E::F::from(BaseField::from_u32_unchecked(1 << r));
        (l, h)
    }

    /// Perform two XOR lookups at width w.
    fn xor2(&mut self, w: u32, a: [E::F; 2], b: [E::F; 2]) -> [E::F; 2] {
        // Read XOR results from trace
        let c = [self.eval.next_trace_mask(), self.eval.next_trace_mask()];

        // Add to LogUp relation
        self.xor_lookup_elements.use_relation(
            &mut self.eval,
            w,
            [
                &[a[0].clone(), b[0].clone(), c[0].clone()],
                &[a[1].clone(), b[1].clone(), c[1].clone()],
            ],
        );

        c
    }
}
