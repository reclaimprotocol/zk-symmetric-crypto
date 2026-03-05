//! ChaCha20 quarter-round AIR constraints.
//!
//! This implements the constraint evaluation for ChaCha20 using Stwo's
//! constraint framework. The approach mirrors the BLAKE example but
//! adapted for ChaCha's LEFT rotation (vs BLAKE's right rotation).
//!
//! ChaCha quarter-round:
//!   a += b; d ^= a; d <<<= 16;
//!   c += d; b ^= c; b <<<= 12;
//!   a += b; d ^= a; d <<<= 8;
//!   c += d; b ^= c; b <<<= 7;
//!
//! XOR widths needed (same as BLAKE):
//!   - 8-bit: for rotation by 16 (split at 8) and rotation by 8 (split at 8)
//!   - 4-bit: for rotation by 12 (split at 4, low part)
//!   - 12-bit: for rotation by 12 (split at 4, high part)
//!   - 9-bit: for rotation by 7 (split at 9, low part)
//!   - 7-bit: for rotation by 7 (split at 9, high part)

use num_traits::One;
use stwo::core::channel::Channel;
use stwo::core::fields::m31::BaseField;
use stwo::prover::backend::simd::m31::PackedBaseField;
use stwo::prover::backend::simd::qm31::PackedSecureField;
use stwo_constraint_framework::{relation, EvalAtRow, Relation, RelationEntry};

use super::Fu32;

/// Inverse of 2^16 in M31, used for carry extraction
const INV16: BaseField = BaseField::from_u32_unchecked(1 << 15);

// Define XOR lookup relations for each width (same as BLAKE)
relation!(XorElements12, 3);
relation!(XorElements9, 3);
relation!(XorElements8, 3);
relation!(XorElements7, 3);
relation!(XorElements4, 3);

/// XOR lookup elements for ChaCha (same widths as BLAKE).
#[derive(Clone)]
pub struct ChaChaXorElements {
    pub xor12: XorElements12,
    pub xor9: XorElements9,
    pub xor8: XorElements8,
    pub xor7: XorElements7,
    pub xor4: XorElements4,
}

impl ChaChaXorElements {
    /// Draw random lookup elements from a channel.
    pub fn draw(channel: &mut impl Channel) -> Self {
        Self {
            xor12: XorElements12::draw(channel),
            xor9: XorElements9::draw(channel),
            xor8: XorElements8::draw(channel),
            xor7: XorElements7::draw(channel),
            xor4: XorElements4::draw(channel),
        }
    }

    /// Create dummy elements for testing.
    pub fn dummy() -> Self {
        Self {
            xor12: XorElements12::dummy(),
            xor9: XorElements9::dummy(),
            xor8: XorElements8::dummy(),
            xor7: XorElements7::dummy(),
            xor4: XorElements4::dummy(),
        }
    }

    /// Add XOR lookups to the relation based on width.
    pub fn use_relation<E: EvalAtRow>(&self, eval: &mut E, w: u32, values: [&[E::F]; 2]) {
        match w {
            12 => {
                eval.add_to_relation(RelationEntry::new(&self.xor12, E::EF::one(), values[0]));
                eval.add_to_relation(RelationEntry::new(&self.xor12, E::EF::one(), values[1]));
            }
            9 => {
                eval.add_to_relation(RelationEntry::new(&self.xor9, E::EF::one(), values[0]));
                eval.add_to_relation(RelationEntry::new(&self.xor9, E::EF::one(), values[1]));
            }
            8 => {
                eval.add_to_relation(RelationEntry::new(&self.xor8, E::EF::one(), values[0]));
                eval.add_to_relation(RelationEntry::new(&self.xor8, E::EF::one(), values[1]));
            }
            7 => {
                eval.add_to_relation(RelationEntry::new(&self.xor7, E::EF::one(), values[0]));
                eval.add_to_relation(RelationEntry::new(&self.xor7, E::EF::one(), values[1]));
            }
            4 => {
                eval.add_to_relation(RelationEntry::new(&self.xor4, E::EF::one(), values[0]));
                eval.add_to_relation(RelationEntry::new(&self.xor4, E::EF::one(), values[1]));
            }
            _ => panic!("Invalid XOR width: {}", w),
        }
    }

    /// Combine values using the appropriate XOR relation for trace generation.
    pub fn combine(&self, w: u32, values: &[PackedBaseField]) -> PackedSecureField {
        match w {
            12 => self.xor12.combine(values),
            9 => self.xor9.combine(values),
            8 => self.xor8.combine(values),
            7 => self.xor7.combine(values),
            4 => self.xor4.combine(values),
            _ => panic!("Invalid XOR width: {}", w),
        }
    }
}

/// Constraint evaluator for a ChaCha quarter-round.
pub struct ChaChaQuarterRoundEval<'a, E: EvalAtRow> {
    pub eval: E,
    pub xor_lookup_elements: &'a ChaChaXorElements,
}

impl<'a, E: EvalAtRow> ChaChaQuarterRoundEval<'a, E> {
    /// Evaluate constraints for a full quarter-round.
    ///
    /// Input: 4 u32 values (a, b, c, d) from the trace
    /// Output: 4 u32 values after the quarter-round
    pub fn eval_quarter_round(mut self) -> (E, [Fu32<E::F>; 4]) {
        // Read initial state from trace
        let mut a = self.next_u32();
        let mut b = self.next_u32();
        let mut c = self.next_u32();
        let mut d = self.next_u32();

        // a += b; d ^= a; d <<<= 16;
        a = self.add2_u32(a, b.clone());
        d = self.xor_rotl16_u32(d, a.clone());

        // c += d; b ^= c; b <<<= 12;
        c = self.add2_u32(c, d.clone());
        b = self.xor_rotl_u32(b, c.clone(), 12);

        // a += b; d ^= a; d <<<= 8;
        a = self.add2_u32(a, b.clone());
        d = self.xor_rotl_u32(d, a.clone(), 8);

        // c += d; b ^= c; b <<<= 7;
        c = self.add2_u32(c, d.clone());
        b = self.xor_rotl_u32(b, c.clone(), 7);

        (self.eval, [a, b, c, d])
    }

    /// Read next u32 from trace (as two 16-bit field elements)
    fn next_u32(&mut self) -> Fu32<E::F> {
        let l = self.eval.next_trace_mask();
        let h = self.eval.next_trace_mask();
        Fu32 { l, h }
    }

    /// Add two u32s with carry constraint.
    ///
    /// For a + b = s (mod 2^32):
    /// - s_l = (a_l + b_l) mod 2^16
    /// - carry_l = (a_l + b_l) / 2^16 ∈ {0, 1}
    /// - s_h = (a_h + b_h + carry_l) mod 2^16
    /// - carry_h = (a_h + b_h + carry_l) / 2^16 ∈ {0, 1}
    fn add2_u32(&mut self, a: Fu32<E::F>, b: Fu32<E::F>) -> Fu32<E::F> {
        // Read result from trace
        let sl = self.eval.next_trace_mask();
        let sh = self.eval.next_trace_mask();

        // Constrain carry_l ∈ {0, 1}
        // carry_l = (a.l + b.l - sl) / 2^16
        let carry_l = (a.l.clone() + b.l.clone() - sl.clone()) * E::F::from(INV16);
        self.eval
            .add_constraint(carry_l.clone() * carry_l.clone() - carry_l.clone());

        // Constrain carry_h ∈ {0, 1}
        let carry_h = (a.h + b.h + carry_l - sh.clone()) * E::F::from(INV16);
        self.eval
            .add_constraint(carry_h.clone() * carry_h.clone() - carry_h.clone());

        Fu32 { l: sl, h: sh }
    }

    /// XOR and left-rotate by 16 bits (just swaps the halves).
    ///
    /// For c = (a ^ b) <<< 16:
    /// - c_l = a_h ^ b_h
    /// - c_h = a_l ^ b_l
    fn xor_rotl16_u32(&mut self, a: Fu32<E::F>, b: Fu32<E::F>) -> Fu32<E::F> {
        // Split each half at 8 bits for XOR lookups
        let (all, alh) = self.split(a.l.clone(), 8);
        let (ahl, ahh) = self.split(a.h.clone(), 8);
        let (bll, blh) = self.split(b.l.clone(), 8);
        let (bhl, bhh) = self.split(b.h.clone(), 8);

        // XOR lookups (8-bit width)
        let [xorll, xorhl] = self.xor2(8, [all, ahl], [bll, bhl]);
        let [xorlh, xorhh] = self.xor2(8, [alh, ahh], [blh, bhh]);

        // Reassemble with rotation by 16 (swap halves)
        // result_l = (xor of high halves) = xorhh * 256 + xorhl
        // result_h = (xor of low halves) = xorlh * 256 + xorll
        Fu32 {
            l: xorhh * E::F::from(BaseField::from_u32_unchecked(1 << 8)) + xorhl,
            h: xorlh * E::F::from(BaseField::from_u32_unchecked(1 << 8)) + xorll,
        }
    }

    /// XOR and left-rotate by r bits (0 < r < 16).
    ///
    /// For c = (a ^ b) <<< r:
    /// We decompose each 16-bit half at position (16-r):
    ///   a_l = a_l_high * 2^(16-r) + a_l_low
    ///   a_h = a_h_high * 2^(16-r) + a_h_low
    ///
    /// After XOR and left rotation by r:
    ///   result_l = (c_l_low << r) | c_h_high
    ///   result_h = (c_h_low << r) | c_l_high
    fn xor_rotl_u32(&mut self, a: Fu32<E::F>, b: Fu32<E::F>, r: u32) -> Fu32<E::F> {
        // Split at (16-r) to get: low (16-r bits) and high (r bits)
        let (all, alh) = self.split(a.l.clone(), 16 - r);  // alh is top r bits
        let (ahl, ahh) = self.split(a.h.clone(), 16 - r);  // ahh is top r bits
        let (bll, blh) = self.split(b.l.clone(), 16 - r);
        let (bhl, bhh) = self.split(b.h.clone(), 16 - r);

        // XOR the corresponding parts
        // Low parts are (16-r) bits, high parts are r bits
        let [xorll, xorhl] = self.xor2(16 - r, [all, ahl], [bll, bhl]);  // c_l_low, c_h_low
        let [xorlh, xorhh] = self.xor2(r, [alh, ahh], [blh, bhh]);        // c_l_high, c_h_high

        // Reassemble with left rotation
        // result_l = (c_l_low << r) | c_h_high = xorll * 2^r + xorhh
        // result_h = (c_h_low << r) | c_l_high = xorhl * 2^r + xorlh
        let shift = E::F::from(BaseField::from_u32_unchecked(1 << r));
        Fu32 {
            l: xorll * shift.clone() + xorhh,
            h: xorhl * shift + xorlh,
        }
    }

    /// Split a field element at position r.
    /// Returns (low r bits, high 16-r bits).
    /// The high part is read from the trace (prover provides it).
    fn split(&mut self, a: E::F, r: u32) -> (E::F, E::F) {
        let h = self.eval.next_trace_mask();  // High part from trace
        let l = a - h.clone() * E::F::from(BaseField::from_u32_unchecked(1 << r));
        (l, h)
    }

    /// Perform two XOR lookups at width w.
    /// Returns [a[0]^b[0], a[1]^b[1]].
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

#[cfg(test)]
mod tests {
    // TODO: Add constraint evaluation tests
}
