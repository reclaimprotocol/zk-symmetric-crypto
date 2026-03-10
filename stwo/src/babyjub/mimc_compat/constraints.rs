//! MiMC hash constraint evaluation for stwo circuits.
//!
//! Implements MiMC over BN254 scalar field with 110 rounds of x^5.
//! This matches gnark-crypto's MiMC implementation for cross-system compatibility.

use stwo_constraint_framework::EvalAtRow;

use crate::babyjub::field256::constraints::Field256EvalAtRow;
use crate::babyjub::field256::{field256_from_limbs, Field256, N_LIMBS, LIMB_BITS};

use super::constants::MIMC_CONSTANTS;

/// Number of MiMC rounds (matches gnark-crypto).
pub const MIMC_ROUNDS: usize = 110;

/// Evaluator for MiMC hash constraints.
pub struct MiMCEvalAtRow<'a, E: EvalAtRow> {
    pub field_eval: Field256EvalAtRow<'a, E>,
}

impl<E: EvalAtRow> MiMCEvalAtRow<'_, E> {
    /// Get MiMC round constant as Field256.
    fn round_constant(&self, round: usize) -> Field256<E::F> {
        // Convert u256 constant to 13-bit limbs
        let c = &MIMC_CONSTANTS[round];
        let mut limbs = [0u32; N_LIMBS];

        // Convert from [u32; 8] (32-bit limbs) to [u32; 20] (13-bit limbs)
        let mut bit_buffer: u64 = 0;
        let mut buffer_bits: u32 = 0;
        let mut input_idx = 0;
        let mut output_idx = 0;
        let limb_mask = (1u32 << LIMB_BITS) - 1;

        while output_idx < N_LIMBS {
            while buffer_bits < LIMB_BITS && input_idx < 8 {
                bit_buffer |= (c[input_idx] as u64) << buffer_bits;
                buffer_bits += 32;
                input_idx += 1;
            }
            limbs[output_idx] = (bit_buffer as u32) & limb_mask;
            bit_buffer >>= LIMB_BITS;
            buffer_bits = buffer_bits.saturating_sub(LIMB_BITS);
            output_idx += 1;
        }

        field256_from_limbs(&limbs)
    }

    /// Constrain MiMC encryption: encrypt(message, key) using 110 rounds of x^5.
    ///
    /// For each round i:
    ///   tmp = m + k + c[i]
    ///   m = tmp^5
    /// Return m + k
    ///
    /// The prover provides intermediate values for each round.
    pub fn mimc_encrypt(
        &mut self,
        message: &Field256<E::F>,
        key: &Field256<E::F>,
    ) -> Field256<E::F> {
        let mut m = message.clone();

        for round in 0..MIMC_ROUNDS {
            let c_i = self.round_constant(round);

            // tmp = m + k + c[i]
            let m_plus_k = self.field_eval.add_field256(&m, key);
            let tmp = self.field_eval.add_field256(&m_plus_k, &c_i);

            // m = tmp^5 = tmp^2 * tmp^2 * tmp
            let tmp2 = self.field_eval.mul_field256(&tmp, &tmp);
            let tmp4 = self.field_eval.mul_field256(&tmp2, &tmp2);
            m = self.field_eval.mul_field256(&tmp4, &tmp);
        }

        // Return m + k
        self.field_eval.add_field256(&m, key)
    }

    /// Constrain MiMC hash using Miyaguchi-Preneel construction.
    ///
    /// h = 0
    /// for each element in data:
    ///   r = encrypt(element, h)
    ///   h = h + r + element
    /// return h
    pub fn mimc_hash(&mut self, data: &[Field256<E::F>]) -> Field256<E::F> {
        let mut h = Field256::<E::F>::zero();

        for element in data {
            let r = self.mimc_encrypt(element, &h);
            // h = h + r + element
            let h_plus_r = self.field_eval.add_field256(&h, &r);
            h = self.field_eval.add_field256(&h_plus_r, element);
        }

        h
    }

    /// Constrain MiMC hash for exactly 3 elements (used for hash-to-point).
    pub fn mimc_hash_3(
        &mut self,
        a: &Field256<E::F>,
        b: &Field256<E::F>,
        c: &Field256<E::F>,
    ) -> Field256<E::F> {
        self.mimc_hash(&[a.clone(), b.clone(), c.clone()])
    }

    /// Constrain MiMC hash for exactly 4 elements (used for final output hash).
    pub fn mimc_hash_4(
        &mut self,
        a: &Field256<E::F>,
        b: &Field256<E::F>,
        c: &Field256<E::F>,
        d: &Field256<E::F>,
    ) -> Field256<E::F> {
        self.mimc_hash(&[a.clone(), b.clone(), c.clone(), d.clone()])
    }
}

/// Estimate constraint count for MiMC encryption (110 rounds).
pub fn mimc_encrypt_constraint_count() -> usize {
    use crate::babyjub::field256::constraints::{add_constraint_count, mul_constraint_count};

    // Per round: 2 additions + 3 multiplications
    let per_round = 2 * add_constraint_count() + 3 * mul_constraint_count();

    // 110 rounds + final addition
    MIMC_ROUNDS * per_round + add_constraint_count()
}

/// Estimate constraint count for MiMC hash of n elements.
pub fn mimc_hash_constraint_count(n: usize) -> usize {
    use crate::babyjub::field256::constraints::add_constraint_count;

    // Per element: 1 encrypt + 2 additions
    let per_element = mimc_encrypt_constraint_count() + 2 * add_constraint_count();

    n * per_element
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mimc_constraint_counts() {
        println!("MiMC encrypt constraints: {}", mimc_encrypt_constraint_count());
        println!("MiMC hash(3) constraints: {}", mimc_hash_constraint_count(3));
        println!("MiMC hash(4) constraints: {}", mimc_hash_constraint_count(4));

        // Verify reasonable estimates
        assert!(mimc_encrypt_constraint_count() > 10000);
    }
}
