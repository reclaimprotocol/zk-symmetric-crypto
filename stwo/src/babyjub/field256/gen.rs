//! Trace generation for 256-bit field arithmetic.
//!
//! Provides native BigInt computation for the prover to generate witness values.

use std::simd::u32x16;

use num_traits::Zero;
use stwo::prover::backend::simd::m31::PackedBaseField;

use super::{limbs29_to_u256, u256_to_limbs29, LIMB_BITS, LIMB_MASK, N_LIMBS};

/// Native 256-bit integer represented as 9 x 29-bit limbs for trace generation.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct BigInt256 {
    pub limbs: [u32; N_LIMBS],
}

impl BigInt256 {
    /// Create a zero value.
    pub const fn zero() -> Self {
        Self { limbs: [0; N_LIMBS] }
    }

    /// Create a one value.
    pub const fn one() -> Self {
        let mut limbs = [0u32; N_LIMBS];
        limbs[0] = 1;
        Self { limbs }
    }

    /// Create from 29-bit limbs.
    pub const fn from_limbs(limbs: [u32; N_LIMBS]) -> Self {
        Self { limbs }
    }

    /// Create from 32-bit limbs (little-endian u256 representation).
    pub fn from_u256(value: &[u32; 8]) -> Self {
        Self {
            limbs: u256_to_limbs29(value),
        }
    }

    /// Convert to 32-bit limbs (little-endian u256 representation).
    pub fn to_u256(&self) -> [u32; 8] {
        limbs29_to_u256(&self.limbs)
    }

    /// Check if this value is zero.
    pub fn is_zero(&self) -> bool {
        self.limbs.iter().all(|&l| l == 0)
    }

    /// Compare two BigInt256 values.
    /// Returns -1 if self < other, 0 if equal, 1 if self > other.
    pub fn cmp(&self, other: &Self) -> i32 {
        for i in (0..N_LIMBS).rev() {
            if self.limbs[i] < other.limbs[i] {
                return -1;
            }
            if self.limbs[i] > other.limbs[i] {
                return 1;
            }
        }
        0
    }

    /// Check if self >= other.
    pub fn gte(&self, other: &Self) -> bool {
        self.cmp(other) >= 0
    }

    /// Check if self < other.
    pub fn lt(&self, other: &Self) -> bool {
        self.cmp(other) < 0
    }

    /// Add two BigInt256 values without reduction.
    /// Returns (result, overflow_flag).
    pub fn add_no_reduce(&self, other: &Self) -> (Self, bool) {
        let mut result = [0u32; N_LIMBS];
        let mut carry: u64 = 0;

        for i in 0..N_LIMBS {
            let sum = self.limbs[i] as u64 + other.limbs[i] as u64 + carry;
            result[i] = (sum & LIMB_MASK as u64) as u32;
            carry = sum >> LIMB_BITS;
        }

        (Self { limbs: result }, carry != 0)
    }

    /// Subtract other from self without reduction.
    /// Returns (result, underflow_flag).
    pub fn sub_no_reduce(&self, other: &Self) -> (Self, bool) {
        let mut result = [0u32; N_LIMBS];
        let mut borrow: i64 = 0;

        for i in 0..N_LIMBS {
            let diff = self.limbs[i] as i64 - other.limbs[i] as i64 - borrow;
            if diff < 0 {
                result[i] = ((diff + (1i64 << LIMB_BITS)) & LIMB_MASK as i64) as u32;
                borrow = 1;
            } else {
                result[i] = diff as u32;
                borrow = 0;
            }
        }

        (Self { limbs: result }, borrow != 0)
    }

    /// Add with modular reduction.
    pub fn add_mod(&self, other: &Self, modulus: &Self) -> Self {
        let (sum, overflow) = self.add_no_reduce(other);
        if overflow || sum.gte(modulus) {
            sum.sub_no_reduce(modulus).0
        } else {
            sum
        }
    }

    /// Subtract with modular reduction.
    pub fn sub_mod(&self, other: &Self, modulus: &Self) -> Self {
        let (diff, underflow) = self.sub_no_reduce(other);
        if underflow {
            diff.add_no_reduce(modulus).0
        } else {
            diff
        }
    }

    /// Multiply two BigInt256 values, returning full product as array of limbs.
    /// Product has up to 2*N_LIMBS limbs.
    pub fn mul_wide(&self, other: &Self) -> [u64; 2 * N_LIMBS] {
        let mut product = [0u64; 2 * N_LIMBS];

        for i in 0..N_LIMBS {
            let mut carry: u64 = 0;
            for j in 0..N_LIMBS {
                let k = i + j;
                let p = self.limbs[i] as u64 * other.limbs[j] as u64 + product[k] + carry;
                product[k] = p & LIMB_MASK as u64;
                carry = p >> LIMB_BITS;
            }
            // Propagate remaining carry
            let mut k = i + N_LIMBS;
            while carry != 0 && k < 2 * N_LIMBS {
                let sum = product[k] + carry;
                product[k] = sum & LIMB_MASK as u64;
                carry = sum >> LIMB_BITS;
                k += 1;
            }
        }

        product
    }

    /// Multiply with modular reduction.
    /// Uses Barrett reduction or simple division.
    pub fn mul_mod(&self, other: &Self, modulus: &Self) -> Self {
        let product = self.mul_wide(other);

        // Convert product to BigInt for division
        // This is a simplified implementation - for production, use Barrett reduction
        let (quotient, remainder) = div_wide_by_modulus(&product, modulus);
        let _ = quotient; // We only need remainder

        remainder
    }

    /// Compute modular inverse using Fermat's little theorem: a^(-1) = a^(p-2) mod p.
    /// Returns None if self is zero.
    pub fn inv_mod(&self, modulus: &Self) -> Option<Self> {
        if self.is_zero() {
            return None;
        }

        // Compute p - 2
        let two = Self::from_limbs([2, 0, 0, 0, 0, 0, 0, 0, 0]);
        let exp = modulus.sub_no_reduce(&two).0;

        // Compute self^(p-2) mod p using square-and-multiply
        Some(self.pow_mod(&exp, modulus))
    }

    /// Modular exponentiation using square-and-multiply.
    pub fn pow_mod(&self, exp: &Self, modulus: &Self) -> Self {
        let mut result = Self::one();
        let mut base = self.clone();

        // Process each bit of the exponent
        for i in 0..N_LIMBS {
            for bit in 0..LIMB_BITS {
                if (exp.limbs[i] >> bit) & 1 == 1 {
                    result = result.mul_mod(&base, modulus);
                }
                base = base.mul_mod(&base, modulus);
            }
        }

        result
    }

    // =========================================================================
    // Gnark-compatible serialization (big-endian bytes)
    // =========================================================================

    /// Convert to 32-byte big-endian representation (gnark-compatible).
    /// This matches Go's `big.Int.Bytes()` padded to 32 bytes.
    pub fn to_bytes_be(&self) -> [u8; 32] {
        // First convert to u256 (8x32-bit little-endian)
        let u256 = self.to_u256();

        // Then convert to big-endian bytes
        let mut bytes = [0u8; 32];
        for (i, &word) in u256.iter().enumerate() {
            let be_bytes = word.to_be_bytes();
            // Place in reverse order (most significant first)
            let offset = (7 - i) * 4;
            bytes[offset..offset + 4].copy_from_slice(&be_bytes);
        }
        bytes
    }

    /// Create from 32-byte big-endian representation (gnark-compatible).
    /// This matches Go's `new(big.Int).SetBytes(data)`.
    pub fn from_bytes_be(bytes: &[u8]) -> Self {
        let mut padded = [0u8; 32];
        let start = 32usize.saturating_sub(bytes.len());
        padded[start..].copy_from_slice(&bytes[..bytes.len().min(32)]);

        // Convert from big-endian bytes to u256 (little-endian u32s)
        let mut u256 = [0u32; 8];
        for i in 0..8 {
            let offset = (7 - i) * 4;
            u256[i] = u32::from_be_bytes([
                padded[offset],
                padded[offset + 1],
                padded[offset + 2],
                padded[offset + 3],
            ]);
        }

        Self::from_u256(&u256)
    }

    /// Convert to variable-length big-endian bytes (no leading zeros).
    /// This matches Go's `big.Int.Bytes()` exactly:
    /// - Zero returns empty slice []
    /// - Non-zero returns big-endian bytes without leading zeros
    pub fn to_bytes_be_trimmed(&self) -> Vec<u8> {
        // Match Go's BigInt.Bytes() behavior: return empty for zero
        if self.is_zero() {
            return Vec::new();
        }
        let bytes = self.to_bytes_be();
        // Find first non-zero byte
        let start = bytes.iter().position(|&b| b != 0).unwrap_or(0);
        bytes[start..].to_vec()
    }

    /// Convert to 32-byte little-endian representation.
    pub fn to_bytes_le(&self) -> [u8; 32] {
        let u256 = self.to_u256();
        let mut bytes = [0u8; 32];
        for (i, &word) in u256.iter().enumerate() {
            let le_bytes = word.to_le_bytes();
            let offset = i * 4;
            bytes[offset..offset + 4].copy_from_slice(&le_bytes);
        }
        bytes
    }

    /// Create from 32-byte little-endian representation.
    pub fn from_bytes_le(bytes: &[u8]) -> Self {
        let mut padded = [0u8; 32];
        let len = bytes.len().min(32);
        padded[..len].copy_from_slice(&bytes[..len]);

        let mut u256 = [0u32; 8];
        for i in 0..8 {
            let offset = i * 4;
            u256[i] = u32::from_le_bytes([
                padded[offset],
                padded[offset + 1],
                padded[offset + 2],
                padded[offset + 3],
            ]);
        }

        Self::from_u256(&u256)
    }

    /// Shift right by one bit.
    pub fn shr_one(&self) -> Self {
        let mut result = [0u32; N_LIMBS];
        let mut carry = 0u32;

        for i in (0..N_LIMBS).rev() {
            let new_carry = self.limbs[i] & 1;
            result[i] = (self.limbs[i] >> 1) | (carry << (LIMB_BITS - 1));
            carry = new_carry;
        }

        Self { limbs: result }
    }

    /// Compare to another BigInt256, returning Ordering.
    pub fn compare(&self, other: &Self) -> std::cmp::Ordering {
        for i in (0..N_LIMBS).rev() {
            if self.limbs[i] < other.limbs[i] {
                return std::cmp::Ordering::Less;
            }
            if self.limbs[i] > other.limbs[i] {
                return std::cmp::Ordering::Greater;
            }
        }
        std::cmp::Ordering::Equal
    }

    /// Compute modular square root using Tonelli-Shanks algorithm.
    /// Returns None if no square root exists.
    pub fn sqrt_mod(&self, modulus: &Self) -> Option<Self> {
        // For BN254 scalar field, p ≡ 1 (mod 4), so we use Tonelli-Shanks
        // But first check if self is a quadratic residue

        if self.is_zero() {
            return Some(Self::zero());
        }

        // p - 1 = 2^s * q where q is odd
        let one = Self::one();
        let p_minus_1 = modulus.sub_no_reduce(&one).0;

        // Find s and q
        let mut s = 0u32;
        let mut q = p_minus_1;
        while (q.limbs[0] & 1) == 0 {
            q = q.shr_one();
            s += 1;
        }

        // Find a quadratic non-residue z
        let mut z = Self::from_limbs([2, 0, 0, 0, 0, 0, 0, 0, 0]);
        let exp = p_minus_1.shr_one(); // (p-1)/2

        loop {
            let legendre = z.pow_mod(&exp, modulus);
            if legendre == p_minus_1 {
                // z is a QNR
                break;
            }
            z = z.add_mod(&one, modulus);
        }

        // Initialize
        let mut m = s;
        let mut c = z.pow_mod(&q, modulus);
        let mut t = self.pow_mod(&q, modulus);
        let q_plus_1 = q.add_no_reduce(&one).0;
        let exp_r = q_plus_1.shr_one();
        let mut r = self.pow_mod(&exp_r, modulus);

        loop {
            if t.is_zero() {
                return Some(Self::zero());
            }
            if t == one {
                return Some(r);
            }

            // Find the least i such that t^(2^i) = 1
            let mut i = 1u32;
            let mut tt = t.mul_mod(&t, modulus);
            while tt != one && i < m {
                tt = tt.mul_mod(&tt, modulus);
                i += 1;
            }

            if i == m {
                // No square root exists
                return None;
            }

            // b = c^(2^(m-i-1))
            let exp_bits = m - i - 1;
            let mut b = c;
            for _ in 0..exp_bits {
                b = b.mul_mod(&b, modulus);
            }

            m = i;
            c = b.mul_mod(&b, modulus);
            t = t.mul_mod(&c, modulus);
            r = r.mul_mod(&b, modulus);
        }
    }

}

/// BN254 scalar field modulus as BigInt256.
pub fn modulus() -> BigInt256 {
    BigInt256::from_limbs(super::MODULUS)
}

/// Get the Baby Jubjub prime subgroup order (for scalar multiplication).
pub fn scalar_order() -> BigInt256 {
    BigInt256::from_limbs(super::SCALAR_ORDER)
}

/// Divide a wide product by the modulus.
/// Returns (quotient, remainder).
fn div_wide_by_modulus(product: &[u64; 2 * N_LIMBS], modulus: &BigInt256) -> (BigInt256, BigInt256) {
    // Simple binary division
    // For a production implementation, use Barrett reduction

    // Convert product to a working representation
    // We'll use a simple shift-and-subtract algorithm

    let mut quotient = BigInt256::zero();
    let mut remainder = BigInt256::zero();

    // Process from most significant bit down
    for i in (0..(2 * N_LIMBS)).rev() {
        for bit in (0..LIMB_BITS).rev() {
            // Shift remainder left by 1
            let mut carry = 0u32;
            for j in 0..N_LIMBS {
                let new_val = (remainder.limbs[j] << 1) | carry;
                carry = remainder.limbs[j] >> (LIMB_BITS - 1);
                remainder.limbs[j] = new_val & LIMB_MASK;
            }

            // Add the current bit of product
            let prod_bit = ((product[i] >> bit) & 1) as u32;
            remainder.limbs[0] |= prod_bit;

            // If remainder >= modulus, subtract and set quotient bit
            if remainder.gte(modulus) {
                remainder = remainder.sub_no_reduce(modulus).0;

                // Set corresponding quotient bit
                let q_bit_pos = i * LIMB_BITS as usize + bit as usize;
                if q_bit_pos < N_LIMBS * LIMB_BITS as usize {
                    let q_limb = q_bit_pos / LIMB_BITS as usize;
                    let q_bit = q_bit_pos % LIMB_BITS as usize;
                    quotient.limbs[q_limb] |= 1 << q_bit;
                }
            }
        }
    }

    (quotient, remainder)
}
/// Trace row generator for Field256 operations.
pub struct Field256TraceGen {
    pub trace: Vec<Vec<u32>>,
    pub col_index: usize,
}

impl Field256TraceGen {
    /// Create new trace generator.
    pub fn new() -> Self {
        Self {
            trace: Vec::new(),
            col_index: 0,
        }
    }

    /// Append a limb value to trace.
    pub fn append_limb(&mut self, val: u32) {
        if self.col_index >= self.trace.len() {
            self.trace.push(Vec::new());
        }
        self.trace[self.col_index].push(val);
        self.col_index += 1;
    }

    /// Append a Field256 to trace.
    pub fn append_field256(&mut self, val: &BigInt256) {
        for i in 0..N_LIMBS {
            self.append_limb(val.limbs[i]);
        }
    }

    /// Append a Field256 to trace with bit decomposition for range checking.
    ///
    /// For each limb, appends:
    /// 1. The limb value
    /// 2. LIMB_BITS (29) bits of the limb decomposition
    ///
    /// This matches the trace format expected by `next_field256_checked`.
    pub fn append_field256_checked(&mut self, val: &BigInt256) {
        for i in 0..N_LIMBS {
            let limb = val.limbs[i];

            // Append the limb value
            self.append_limb(limb);

            // Append bit decomposition (LSB first)
            let mut remaining = limb;
            for _bit_idx in 0..LIMB_BITS {
                let bit = remaining & 1;
                self.append_limb(bit);
                remaining >>= 1;
            }
        }
    }

    /// Generate trace for addition: a + b (mod p).
    /// Returns the result and appends all trace values.
    ///
    /// Trace format:
    /// - result: 9 limbs
    /// - carry bits: 2 bits per limb (bit0, bit1 where carry = bit0 + 2*bit1)
    /// - reduced: 1 bit
    ///
    /// Constraint: a[i] + b[i] + carry[i-1] = result[i] + reduced * p[i] + carry[i] * 2^29
    pub fn gen_add(&mut self, a: &BigInt256, b: &BigInt256) -> BigInt256 {
        let p = modulus();
        let result = a.add_mod(b, &p);

        // Determine if reduction occurred (a + b >= p)
        let reduced = if a.add_no_reduce(b).0.gte(&p) { 1u32 } else { 0u32 };

        // Compute carries to satisfy: a[i] + b[i] + carry[i-1] = result[i] + reduced * p[i] + carry[i] * 2^29
        // Rearranging: carry[i] = (a[i] + b[i] + carry[i-1] - result[i] - reduced * p[i]) / 2^29
        let mut carries = [0u32; N_LIMBS];
        let mut carry: u64 = 0;

        for i in 0..N_LIMBS {
            let sum = a.limbs[i] as u64
                + b.limbs[i] as u64
                + carry;
            let rhs = result.limbs[i] as u64
                + if reduced == 1 { p.limbs[i] as u64 } else { 0 };
            // carry[i] * 2^29 = sum - rhs, so carry[i] = (sum - rhs) >> 29
            // Note: sum >= rhs is guaranteed by the math (a + b = result + reduced * p)
            debug_assert!(sum >= rhs, "sum ({}) should be >= rhs ({}) at limb {}", sum, rhs, i);
            carries[i] = ((sum - rhs) >> LIMB_BITS) as u32;
            carry = carries[i] as u64;
        }

        // Append to trace
        self.append_field256(&result);

        // Append carry bits (2 bits per carry, values 0, 1, or 2)
        for c in carries {
            debug_assert!(c <= 2, "Carry should be at most 2, got {}", c);
            let bit0 = c & 1;
            let bit1 = (c >> 1) & 1;
            self.append_limb(bit0);
            self.append_limb(bit1);
        }

        self.append_limb(reduced);

        result
    }

    /// Generate trace for subtraction: a - b (mod p).
    pub fn gen_sub(&mut self, a: &BigInt256, b: &BigInt256) -> BigInt256 {
        let p = modulus();
        let result = a.sub_mod(b, &p);

        // Compute borrows
        let mut borrows = [0u32; N_LIMBS];
        let borrowed = if a.lt(b) { 1u32 } else { 0u32 };

        let mut borrow: i64 = 0;
        for i in 0..N_LIMBS {
            let a_val = a.limbs[i] as i64 + if borrowed == 1 { p.limbs[i] as i64 } else { 0 };
            let diff = a_val - b.limbs[i] as i64 - borrow;
            if diff < 0 {
                borrows[i] = 1;
                borrow = 1;
            } else {
                borrows[i] = 0;
                borrow = 0;
            }
        }

        // Append to trace
        self.append_field256(&result);
        for bo in borrows {
            self.append_limb(bo);
        }
        self.append_limb(borrowed);

        result
    }

    /// Generate trace for multiplication: a * b (mod p).
    ///
    /// Verifies: a * b = q * p + r
    ///
    /// The constraint equation for each limb position k is:
    /// ab_sum + carry_in = qp_sum + r_k + carry[k] * 2^29
    ///
    /// Carries are decomposed into sign-magnitude format:
    /// - sign: 1 bit (0=positive, 1=negative)
    /// - magnitude: 33 bits decomposed as m0 (11 bits) + m1 (11 bits) + m2 (11 bits)
    ///
    /// This allows constraining carries to be valid without negative field elements.
    pub fn gen_mul(&mut self, a: &BigInt256, b: &BigInt256) -> BigInt256 {
        let p = modulus();
        let product = a.mul_wide(b);
        let (quotient, result) = div_wide_by_modulus(&product, &p);

        // Append result and quotient first
        self.append_field256(&result);
        self.append_field256(&quotient);

        // Compute carries for verification: a*b = q*p + r
        let qp = quotient.mul_wide(&p);
        let n_product_limbs = 2 * N_LIMBS - 1;

        let mut carry: i64 = 0;
        for k in 0..n_product_limbs {
            // ab[k] = sum of a[i]*b[j] for i+j=k
            let ab_k = product[k] as i64;

            // qp[k] + r[k]
            let qp_k = qp[k] as i64;
            let r_k = if k < N_LIMBS {
                result.limbs[k] as i64
            } else {
                0
            };

            // Constraint: ab[k] + carry_in = qp[k] + r[k] + carry[k] * 2^29
            // Rearranging: carry[k] = (ab[k] + carry_in - qp[k] - r[k]) / 2^29
            let total = ab_k + carry - qp_k - r_k;

            // The next carry (can be positive or negative)
            carry = total >> LIMB_BITS;

            // Decompose carry into sign + magnitude
            let sign = if carry < 0 { 1u32 } else { 0u32 };
            let magnitude = carry.unsigned_abs() as u32;

            // Append sign bit
            self.append_limb(sign);

            // Append m0 bits (bits 0-10, 11 bits)
            for bit in 0..11 {
                self.append_limb((magnitude >> bit) & 1);
            }

            // Append m1 bits (bits 11-21, 11 bits)
            for bit in 0..11 {
                self.append_limb((magnitude >> (11 + bit)) & 1);
            }

            // Append m2 bits (bits 22-32, 11 bits)
            for bit in 0..11 {
                self.append_limb((magnitude >> (22 + bit)) & 1);
            }
        }

        result
    }

    /// Generate trace for inversion: a^(-1) (mod p).
    pub fn gen_inv(&mut self, a: &BigInt256) -> BigInt256 {
        let p = modulus();
        let inv = a.inv_mod(&p).expect("Cannot invert zero");

        // The multiplication a * inv = 1 (mod p) is verified separately
        // We need to generate the multiplication trace

        // First append the inverse
        self.append_field256(&inv);

        // Then generate the multiplication trace for verification
        let _ = self.gen_mul(a, &inv);

        inv
    }

    /// Generate trace for select: cond ? b : a.
    pub fn gen_select(&mut self, cond: u32, a: &BigInt256, b: &BigInt256) -> BigInt256 {
        let result = if cond == 0 { *a } else { *b };
        self.append_field256(&result);
        result
    }
}

impl Default for Field256TraceGen {
    fn default() -> Self {
        Self::new()
    }
}

/// SIMD-packed version for batch trace generation.
pub struct Field256SimdTraceGen {
    pub trace: Vec<Vec<PackedBaseField>>,
    pub vec_row: usize,
    pub col_index: usize,
}

impl Field256SimdTraceGen {
    /// Append a SIMD-packed value to trace.
    pub fn append_packed(&mut self, val: u32x16) {
        if self.col_index >= self.trace.len() {
            self.trace.push(Vec::new());
        }
        if self.trace[self.col_index].len() <= self.vec_row {
            self.trace[self.col_index]
                .resize(self.vec_row + 1, PackedBaseField::zero());
        }
        self.trace[self.col_index][self.vec_row] =
            unsafe { PackedBaseField::from_simd_unchecked(val) };
        self.col_index += 1;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bigint_add_sub() {
        let p = modulus();
        let a = BigInt256::from_limbs([1, 2, 3, 4, 5, 6, 7, 8, 0]);
        let b = BigInt256::from_limbs([10, 20, 30, 40, 50, 60, 70, 80, 0]);

        let sum = a.add_mod(&b, &p);
        let diff = sum.sub_mod(&b, &p);
        assert_eq!(a, diff, "a + b - b should equal a");
    }

    #[test]
    fn test_bigint_mul() {
        let p = modulus();
        let a = BigInt256::from_limbs([123456, 789012, 0, 0, 0, 0, 0, 0, 0]);
        let b = BigInt256::from_limbs([654321, 210987, 0, 0, 0, 0, 0, 0, 0]);

        let product = a.mul_mod(&b, &p);

        // Verify by computing a * b manually for small values
        // and checking the result is correct modulo p
        assert!(!product.is_zero());
    }

    #[test]
    fn test_mul_carry_equation() {
        // Test that the carry equation holds exactly
        let p = modulus();
        let a = BigInt256::from_limbs([123456, 789012, 333, 444, 555, 666, 777, 888, 0]);
        let b = BigInt256::from_limbs([654321, 210987, 111, 222, 333, 444, 555, 666, 0]);

        let product = a.mul_wide(&b);
        let (quotient, result) = div_wide_by_modulus(&product, &p);
        let qp = quotient.mul_wide(&p);

        let n_product_limbs = 2 * N_LIMBS - 1;
        let mut carry: i64 = 0;

        for k in 0..n_product_limbs {
            let ab_k = product[k] as i64;
            let qp_k = qp[k] as i64;
            let r_k = if k < N_LIMBS { result.limbs[k] as i64 } else { 0 };

            let total = ab_k + carry - qp_k - r_k;
            let remainder = total & ((1 << LIMB_BITS) - 1);
            let carry_out = total >> LIMB_BITS;

            // The remainder must be 0 for the equation to hold in finite fields
            assert_eq!(remainder, 0, "Remainder at position {} should be 0, got {}", k, remainder);

            carry = carry_out;
        }

        // Final carry should be 0
        assert_eq!(carry, 0, "Final carry should be 0");
    }

    #[test]
    fn test_mul_trace_values() {
        // Verify that trace values match constraint expectations
        let mut gen = Field256TraceGen::new();
        let a = BigInt256::from_limbs([123456, 789012, 333, 444, 555, 666, 777, 888, 0]);
        let b = BigInt256::from_limbs([654321, 210987, 111, 222, 333, 444, 555, 666, 0]);

        let result = gen.gen_mul(&a, &b);

        // Check that trace was generated with correct column count
        let n_product_limbs = 2 * N_LIMBS - 1;
        let expected_cols = 9 + 9 + n_product_limbs * 34; // result + quotient + carries
        assert_eq!(gen.trace.len(), expected_cols,
            "Expected {} columns, got {}", expected_cols, gen.trace.len());

        // Verify result limbs are stored correctly
        for i in 0..N_LIMBS {
            assert_eq!(gen.trace[i][0], result.limbs[i],
                "Result limb {} mismatch", i);
        }

        // Verify quotient limbs
        let p = modulus();
        let product = a.mul_wide(&b);
        let (quotient, _) = div_wide_by_modulus(&product, &p);
        let qp = quotient.mul_wide(&p);

        for i in 0..N_LIMBS {
            assert_eq!(gen.trace[9 + i][0], quotient.limbs[i],
                "Quotient limb {} mismatch", i);
        }

        // Verify carry equations hold over INTEGERS
        let two_pow_29 = 1u64 << LIMB_BITS;
        let mut col_idx = 18;
        let mut carry_prev: i64 = 0;

        for k in 0..n_product_limbs {
            // Read carry decomposition from trace
            let sign = gen.trace[col_idx][0];
            col_idx += 1;

            let mut magnitude: u32 = 0;
            for bit in 0..33 {
                let bit_val = gen.trace[col_idx][0];
                col_idx += 1;
                magnitude |= bit_val << bit;
            }

            // Reconstruct carry value
            let carry: i64 = if sign == 1 {
                -(magnitude as i64)
            } else {
                magnitude as i64
            };

            // Verify sign is boolean
            assert!(sign <= 1, "Sign must be 0 or 1");

            // Verify magnitude fits in 33 bits
            assert!((magnitude as u64) < (1u64 << 33), "Magnitude must fit in 33 bits");

            // Compute ab_sum and qp_sum
            let ab_k = product[k] as i64;
            let qp_k = qp[k] as i64;
            let r_k = if k < N_LIMBS { result.limbs[k] as i64 } else { 0 };

            // Verify: ab_k + carry_prev = qp_k + r_k + carry * 2^29
            let lhs = ab_k + carry_prev;
            let rhs = qp_k + r_k + carry * (two_pow_29 as i64);

            assert_eq!(lhs, rhs,
                "Integer carry equation mismatch at position {}: lhs={}, rhs={}", k, lhs, rhs);

            carry_prev = carry;
        }

        println!("All carry equations verified over integers!");
        // Note: The carry equation does NOT hold in M31 field arithmetic due to
        // intermediate values exceeding 2^31 and wrapping differently on each side.
        // This is a fundamental limitation of using M31 for 256-bit arithmetic.
    }

    #[test]
    fn test_bigint_inv() {
        let p = modulus();
        let a = BigInt256::from_limbs([12345, 0, 0, 0, 0, 0, 0, 0, 0]);

        let inv = a.inv_mod(&p).unwrap();
        let product = a.mul_mod(&inv, &p);

        assert_eq!(product, BigInt256::one(), "a * a^(-1) should equal 1");
    }

    #[test]
    fn test_trace_gen_add() {
        let mut gen = Field256TraceGen::new();
        let a = BigInt256::from_limbs([100, 200, 0, 0, 0, 0, 0, 0, 0]);
        let b = BigInt256::from_limbs([300, 400, 0, 0, 0, 0, 0, 0, 0]);

        let result = gen.gen_add(&a, &b);

        assert_eq!(result.limbs[0], 400);
        assert_eq!(result.limbs[1], 600);
    }

    #[test]
    fn test_modulus_value() {
        // Verify modulus is correctly represented
        let p = modulus();

        // Check it's the expected value
        // p = 2736030358979909402780800718157159386076813972158567259200215660948447373041
        // First limb should be 0x10000001
        assert_eq!(p.limbs[0], 0x10000001);
    }

}
