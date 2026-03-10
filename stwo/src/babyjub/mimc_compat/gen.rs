//! MiMC trace generation for stwo circuits.
//!
//! Generates trace data for MiMC hash verification using 13-bit limbs.
//! All field operations use Field256TraceGen which produces verifiable traces.

use crate::babyjub::field256::gen::{modulus, BigInt256, Field256TraceGen};
use crate::babyjub::field256::{LIMB_BITS, LIMB_MASK, N_LIMBS};

use super::constants::MIMC_CONSTANTS;

/// Number of MiMC rounds (matches gnark-crypto).
pub const MIMC_ROUNDS: usize = 110;

/// MiMC trace generator.
///
/// Generates traces for MiMC hash computations that can be verified by constraints.
pub struct MiMCTraceGen<'a> {
    pub field_gen: &'a mut Field256TraceGen,
}

impl<'a> MiMCTraceGen<'a> {
    /// Create a new MiMC trace generator using the given field trace generator.
    pub fn new(field_gen: &'a mut Field256TraceGen) -> Self {
        Self { field_gen }
    }

    /// Get MiMC round constant as BigInt256 with 13-bit limbs.
    fn round_constant(&self, round: usize) -> BigInt256 {
        // Convert u256 constant (8 x 32-bit limbs, little-endian) to 20 x 13-bit limbs
        let c = &MIMC_CONSTANTS[round];
        let mut limbs = [0u32; N_LIMBS];

        let mut bit_buffer: u64 = 0;
        let mut buffer_bits: u32 = 0;
        let mut input_idx = 0;
        let mut output_idx = 0;

        while output_idx < N_LIMBS {
            while buffer_bits < LIMB_BITS && input_idx < 8 {
                bit_buffer |= (c[input_idx] as u64) << buffer_bits;
                buffer_bits += 32;
                input_idx += 1;
            }
            limbs[output_idx] = (bit_buffer as u32) & LIMB_MASK;
            bit_buffer >>= LIMB_BITS;
            buffer_bits = buffer_bits.saturating_sub(LIMB_BITS);
            output_idx += 1;
        }

        BigInt256::from_limbs(limbs)
    }

    /// Generate trace for MiMC encryption: encrypt(message, key).
    ///
    /// Uses 110 rounds of x^5. For each round:
    ///   tmp = m + k + c[i]
    ///   m = tmp^5
    /// Returns m + k
    ///
    /// This generates all intermediate field operation traces.
    pub fn gen_mimc_encrypt(&mut self, message: &BigInt256, key: &BigInt256) -> BigInt256 {
        let mut m = *message;

        for round in 0..MIMC_ROUNDS {
            let c_i = self.round_constant(round);

            // tmp = m + k + c[i]
            let m_plus_k = self.field_gen.gen_add(&m, key);
            let tmp = self.field_gen.gen_add(&m_plus_k, &c_i);

            // m = tmp^5 = tmp^2 * tmp^2 * tmp
            let tmp2 = self.field_gen.gen_mul(&tmp, &tmp);
            let tmp4 = self.field_gen.gen_mul(&tmp2, &tmp2);
            m = self.field_gen.gen_mul(&tmp4, &tmp);
        }

        // Return m + k
        self.field_gen.gen_add(&m, key)
    }

    /// Generate trace for MiMC hash using Miyaguchi-Preneel construction.
    ///
    /// h = 0
    /// for each element in data:
    ///   r = encrypt(element, h)
    ///   h = h + r + element
    /// return h
    pub fn gen_mimc_hash(&mut self, data: &[BigInt256]) -> BigInt256 {
        let mut h = BigInt256::zero();

        for element in data {
            let r = self.gen_mimc_encrypt(element, &h);
            // h = h + r + element
            let h_plus_r = self.field_gen.gen_add(&h, &r);
            h = self.field_gen.gen_add(&h_plus_r, element);
        }

        h
    }

    /// Generate trace for MiMC hash of exactly 3 elements.
    pub fn gen_mimc_hash_3(
        &mut self,
        a: &BigInt256,
        b: &BigInt256,
        c: &BigInt256,
    ) -> BigInt256 {
        self.gen_mimc_hash(&[*a, *b, *c])
    }

    /// Generate trace for MiMC hash of exactly 4 elements.
    pub fn gen_mimc_hash_4(
        &mut self,
        a: &BigInt256,
        b: &BigInt256,
        c: &BigInt256,
        d: &BigInt256,
    ) -> BigInt256 {
        self.gen_mimc_hash(&[*a, *b, *c, *d])
    }
}

/// Estimate trace columns for MiMC encryption (110 rounds).
pub fn mimc_encrypt_trace_columns() -> usize {
    use crate::babyjub::field256::gen::{add_trace_columns, mul_trace_columns};

    // Per round: 2 additions + 3 multiplications
    let per_round = 2 * add_trace_columns() + 3 * mul_trace_columns();

    // 110 rounds + 1 final addition
    MIMC_ROUNDS * per_round + add_trace_columns()
}

/// Estimate trace columns for MiMC hash of n elements.
pub fn mimc_hash_trace_columns(n: usize) -> usize {
    use crate::babyjub::field256::gen::add_trace_columns;

    // Per element: 1 encrypt + 2 additions
    let per_element = mimc_encrypt_trace_columns() + 2 * add_trace_columns();

    n * per_element
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::babyjub::mimc_compat::mimc_hash;

    #[test]
    fn test_mimc_trace_gen_matches_native() {
        let mut field_gen = Field256TraceGen::new();
        let mut mimc_gen = MiMCTraceGen::new(&mut field_gen);

        let a = BigInt256::from_u32(1);
        let b = BigInt256::from_u32(2);
        let c = BigInt256::from_u32(3);

        // Generate trace and get result
        let trace_result = mimc_gen.gen_mimc_hash_3(&a, &b, &c);

        // Compare with native computation
        let native_result = mimc_hash(&[a, b, c]);

        assert_eq!(
            trace_result, native_result,
            "Trace-generated hash should match native hash"
        );
    }

    #[test]
    fn test_mimc_trace_columns() {
        let encrypt_cols = mimc_encrypt_trace_columns();
        let hash3_cols = mimc_hash_trace_columns(3);
        let hash4_cols = mimc_hash_trace_columns(4);

        println!("MiMC encrypt trace columns: {}", encrypt_cols);
        println!("MiMC hash(3) trace columns: {}", hash3_cols);
        println!("MiMC hash(4) trace columns: {}", hash4_cols);

        // Verify reasonable estimates
        assert!(encrypt_cols > 10000, "Expected >10000 columns for encrypt, got {}", encrypt_cols);
    }

    #[test]
    fn test_round_constant_conversion() {
        let mut field_gen = Field256TraceGen::new();
        let mimc_gen = MiMCTraceGen::new(&mut field_gen);

        // First constant from MIMC_CONSTANTS
        let c0 = mimc_gen.round_constant(0);

        // Verify it's non-zero
        assert!(!c0.is_zero(), "First round constant should not be zero");

        // Verify it matches the native conversion
        let native_c0 = BigInt256::from_u256(&MIMC_CONSTANTS[0]);
        assert_eq!(c0, native_c0, "Round constant should match native conversion");
    }
}
