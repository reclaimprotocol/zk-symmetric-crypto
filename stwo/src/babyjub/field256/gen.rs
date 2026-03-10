//! Trace generation for 256-bit field arithmetic with 20 × 13-bit limbs.

// PackedBaseField no longer used - trace stores M31 directly
use super::{limbs_to_u256, u256_to_limbs, LIMB_BITS, LIMB_MASK, N_LIMBS};

/// Native 256-bit integer as 20 × 13-bit limbs.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct BigInt256 {
    pub limbs: [u32; N_LIMBS],
}

impl BigInt256 {
    pub const fn zero() -> Self { Self { limbs: [0; N_LIMBS] } }
    pub const fn one() -> Self {
        let mut limbs = [0u32; N_LIMBS];
        limbs[0] = 1;
        Self { limbs }
    }
    pub const fn from_limbs(limbs: [u32; N_LIMBS]) -> Self { Self { limbs } }
    pub fn from_u256(value: &[u32; 8]) -> Self { Self { limbs: u256_to_limbs(value) } }
    pub fn to_u256(&self) -> [u32; 8] { limbs_to_u256(&self.limbs) }

    pub const fn from_u32(value: u32) -> Self {
        let mut limbs = [0u32; N_LIMBS];
        limbs[0] = value & LIMB_MASK;
        limbs[1] = (value >> LIMB_BITS) & LIMB_MASK;
        limbs[2] = value >> (2 * LIMB_BITS);
        Self { limbs }
    }

    pub fn from_u64(value: u64) -> Self {
        let mut limbs = [0u32; N_LIMBS];
        let mut v = value;
        for i in 0..N_LIMBS {
            limbs[i] = (v & LIMB_MASK as u64) as u32;
            v >>= LIMB_BITS;
            if v == 0 { break; }
        }
        Self { limbs }
    }

    pub fn is_zero(&self) -> bool { self.limbs.iter().all(|&l| l == 0) }

    pub fn compare(&self, other: &Self) -> std::cmp::Ordering {
        for i in (0..N_LIMBS).rev() {
            if self.limbs[i] != other.limbs[i] {
                return self.limbs[i].cmp(&other.limbs[i]);
            }
        }
        std::cmp::Ordering::Equal
    }

    pub fn gte(&self, other: &Self) -> bool { self.compare(other) != std::cmp::Ordering::Less }
    pub fn lt(&self, other: &Self) -> bool { self.compare(other) == std::cmp::Ordering::Less }

    /// Compare for ordering, returns -1 (Less), 0 (Equal), or 1 (Greater).
    /// Provided for backward compatibility with code using .cmp().
    pub fn cmp(&self, other: &Self) -> i32 {
        match self.compare(other) {
            std::cmp::Ordering::Less => -1,
            std::cmp::Ordering::Equal => 0,
            std::cmp::Ordering::Greater => 1,
        }
    }

    /// Add without reduction, returns (result, overflow).
    pub fn add_no_reduce(&self, other: &Self) -> (Self, bool) {
        let mut result = [0u32; N_LIMBS];
        let mut carry = 0u64;
        for i in 0..N_LIMBS {
            let sum = self.limbs[i] as u64 + other.limbs[i] as u64 + carry;
            result[i] = (sum & LIMB_MASK as u64) as u32;
            carry = sum >> LIMB_BITS;
        }
        (Self { limbs: result }, carry != 0)
    }

    /// Subtract without borrowing from modulus.
    pub fn sub_no_reduce(&self, other: &Self) -> (Self, bool) {
        let mut result = [0u32; N_LIMBS];
        let mut borrow = 0i64;
        for i in 0..N_LIMBS {
            let diff = self.limbs[i] as i64 - other.limbs[i] as i64 - borrow;
            if diff < 0 {
                result[i] = (diff + (1i64 << LIMB_BITS)) as u32;
                borrow = 1;
            } else {
                result[i] = diff as u32;
                borrow = 0;
            }
        }
        (Self { limbs: result }, borrow != 0)
    }

    /// Modular addition.
    pub fn add_mod(&self, other: &Self, p: &Self) -> Self {
        let (sum, _) = self.add_no_reduce(other);
        if sum.gte(p) {
            sum.sub_no_reduce(p).0
        } else {
            sum
        }
    }

    /// Modular subtraction.
    pub fn sub_mod(&self, other: &Self, p: &Self) -> Self {
        if self.lt(other) {
            let (with_p, _) = self.add_no_reduce(p);
            with_p.sub_no_reduce(other).0
        } else {
            self.sub_no_reduce(other).0
        }
    }

    /// Wide multiplication (schoolbook), returns 2*N_LIMBS-1 limbs.
    pub fn mul_wide(&self, other: &Self) -> [u64; 2 * N_LIMBS - 1] {
        let mut result = [0u64; 2 * N_LIMBS - 1];
        for i in 0..N_LIMBS {
            for j in 0..N_LIMBS {
                result[i + j] += self.limbs[i] as u64 * other.limbs[j] as u64;
            }
        }
        result
    }

    /// Modular multiplication using schoolbook with proper reduction.
    pub fn mul_mod(&self, other: &Self, p: &Self) -> Self {
        // Use BigInt256's wide multiplication and then reduce
        // We'll compute a * b mod p using the extended Euclidean property

        // Simple approach: use double-and-add for multiplication
        // This is slower but guaranteed correct

        let mut result = Self::zero();
        let mut base = self.clone();

        // Iterate through bits of other
        for i in 0..N_LIMBS {
            for bit in 0..LIMB_BITS {
                if (other.limbs[i] >> bit) & 1 == 1 {
                    result = result.add_mod(&base, p);
                }
                base = base.add_mod(&base, p); // Double
            }
        }

        result
    }

    fn clone(&self) -> Self {
        Self { limbs: self.limbs }
    }

    /// Modular inversion using extended Euclidean algorithm.
    pub fn inv_mod(&self, p: &Self) -> Option<Self> {
        if self.is_zero() { return None; }

        // Simple binary extended GCD
        let mut u = *self;
        let mut v = *p;
        let mut x1 = Self::one();
        let mut x2 = Self::zero();

        while !u.is_zero() && !v.is_zero() {
            while u.limbs[0] & 1 == 0 {
                u = shr1(&u);
                if x1.limbs[0] & 1 == 0 {
                    x1 = shr1(&x1);
                } else {
                    x1 = shr1(&x1.add_no_reduce(p).0);
                }
            }
            while v.limbs[0] & 1 == 0 {
                v = shr1(&v);
                if x2.limbs[0] & 1 == 0 {
                    x2 = shr1(&x2);
                } else {
                    x2 = shr1(&x2.add_no_reduce(p).0);
                }
            }
            if u.gte(&v) {
                u = u.sub_no_reduce(&v).0;
                x1 = x1.sub_mod(&x2, p);
            } else {
                v = v.sub_no_reduce(&u).0;
                x2 = x2.sub_mod(&x1, p);
            }
        }

        if u.limbs == [1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] {
            Some(x1)
        } else if v.limbs == [1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] {
            Some(x2)
        } else {
            None
        }
    }

    /// Convert to big-endian bytes.
    pub fn to_bytes_be(&self) -> [u8; 32] {
        let u256 = self.to_u256();
        let mut bytes = [0u8; 32];
        for i in 0..8 {
            let word = u256[7 - i];
            bytes[i * 4] = (word >> 24) as u8;
            bytes[i * 4 + 1] = (word >> 16) as u8;
            bytes[i * 4 + 2] = (word >> 8) as u8;
            bytes[i * 4 + 3] = word as u8;
        }
        bytes
    }

    /// Create from big-endian bytes.
    pub fn from_bytes_be(bytes: &[u8]) -> Self {
        let mut u256 = [0u32; 8];
        for i in 0..8.min((bytes.len() + 3) / 4) {
            let idx = bytes.len().saturating_sub((i + 1) * 4);
            let end = bytes.len().saturating_sub(i * 4);
            for j in idx..end {
                u256[i] = (u256[i] << 8) | bytes[j] as u32;
            }
        }
        Self::from_u256(&u256)
    }

    /// Convert to little-endian bytes.
    pub fn to_bytes_le(&self) -> [u8; 32] {
        let u256 = self.to_u256();
        let mut bytes = [0u8; 32];
        for i in 0..8 {
            let word = u256[i];
            bytes[i * 4] = word as u8;
            bytes[i * 4 + 1] = (word >> 8) as u8;
            bytes[i * 4 + 2] = (word >> 16) as u8;
            bytes[i * 4 + 3] = (word >> 24) as u8;
        }
        bytes
    }

    /// Create from little-endian bytes.
    pub fn from_bytes_le(bytes: &[u8]) -> Self {
        let mut u256 = [0u32; 8];
        for i in 0..8.min((bytes.len() + 3) / 4) {
            let offset = i * 4;
            let mut word = 0u32;
            for j in 0..4 {
                if offset + j < bytes.len() {
                    word |= (bytes[offset + j] as u32) << (j * 8);
                }
            }
            u256[i] = word;
        }
        Self::from_u256(&u256)
    }

    /// Right shift by 1 bit (divide by 2).
    pub fn shr_one(&self) -> Self {
        shr1(self)
    }

    /// Convert to big-endian bytes, trimming leading zeros.
    /// Returns a Vec<u8> without leading zero bytes (minimum 1 byte for zero).
    pub fn to_bytes_be_trimmed(&self) -> Vec<u8> {
        let bytes = self.to_bytes_be();
        // Find first non-zero byte
        let first_nonzero = bytes.iter().position(|&b| b != 0).unwrap_or(31);
        bytes[first_nonzero..].to_vec()
    }

    /// Compute modular square root using Tonelli-Shanks algorithm.
    /// Returns None if not a quadratic residue.
    pub fn sqrt_mod(&self, p: &Self) -> Option<Self> {
        if self.is_zero() {
            return Some(Self::zero());
        }

        // Tonelli-Shanks algorithm
        let one = Self::one();

        // Factor out powers of 2 from p-1
        // p - 1 = q * 2^s where q is odd
        let (p_minus_1, _) = p.sub_no_reduce(&one);
        let mut q = p_minus_1;
        let mut s = 0u32;
        while q.limbs[0] & 1 == 0 {
            q = shr1(&q);
            s += 1;
        }

        // Find a quadratic non-residue
        let mut z = Self::from_u32(2);
        let p_minus_1_over_2 = shr1(&p_minus_1);
        loop {
            let legendre = pow_mod(&z, &p_minus_1_over_2, p);
            // If z^((p-1)/2) = -1 (mod p), z is a non-residue
            // -1 mod p = p - 1
            if legendre == p_minus_1 {
                break;
            }
            z = z.add_mod(&one, p);
            if z.limbs[0] > 100 {
                // Safety check - shouldn't happen
                return None;
            }
        }

        // Initialize
        let mut m = s;
        let c = pow_mod(&z, &q, p);
        let mut t = pow_mod(self, &q, p);

        // r = self^((q+1)/2)
        let (q_plus_1, _) = q.add_no_reduce(&one);
        let exp = shr1(&q_plus_1);
        let mut r = pow_mod(self, &exp, p);

        let mut c_val = c;

        loop {
            if t == one {
                // Verify: r^2 = self (mod p)
                let r_sq = r.mul_mod(&r, p);
                if r_sq == *self {
                    return Some(r);
                } else {
                    return None; // Not a QR
                }
            }

            // Find least i > 0 such that t^(2^i) = 1
            let mut i = 0u32;
            let mut temp = t;
            while temp != one {
                temp = temp.mul_mod(&temp, p);
                i += 1;
                if i >= m {
                    return None; // Not a quadratic residue
                }
            }

            // b = c^(2^(m-i-1))
            let mut b = c_val;
            for _ in 0..(m - i - 1) {
                b = b.mul_mod(&b, p);
            }

            r = r.mul_mod(&b, p);
            c_val = b.mul_mod(&b, p);
            t = t.mul_mod(&c_val, p);
            m = i;
        }
    }
}

/// Modular exponentiation using square-and-multiply.
fn pow_mod(base: &BigInt256, exp: &BigInt256, p: &BigInt256) -> BigInt256 {
    if exp.is_zero() {
        return BigInt256::one();
    }

    let mut result = BigInt256::one();
    let mut b = *base;

    for i in 0..N_LIMBS {
        for bit in 0..LIMB_BITS {
            if (exp.limbs[i] >> bit) & 1 == 1 {
                result = result.mul_mod(&b, p);
            }
            b = b.mul_mod(&b, p);
        }
    }

    result
}

fn shr1(x: &BigInt256) -> BigInt256 {
    let mut result = [0u32; N_LIMBS];
    for i in 0..N_LIMBS - 1 {
        result[i] = (x.limbs[i] >> 1) | ((x.limbs[i + 1] & 1) << (LIMB_BITS - 1));
    }
    result[N_LIMBS - 1] = x.limbs[N_LIMBS - 1] >> 1;
    BigInt256 { limbs: result }
}

/// Multiply two 256-bit numbers, returning a 512-bit result.
fn mul_u256(a: &[u32; 8], b: &[u32; 8]) -> [u32; 16] {
    let mut result = [0u64; 16];
    for i in 0..8 {
        for j in 0..8 {
            result[i + j] += a[i] as u64 * b[j] as u64;
        }
    }
    // Normalize carries
    for i in 0..15 {
        result[i + 1] += result[i] >> 32;
        result[i] &= 0xFFFFFFFF;
    }
    std::array::from_fn(|i| result[i] as u32)
}

/// Left shift a 512-bit number by `bits` positions.
fn shl_u512(a: &[u32; 16], bits: usize) -> [u32; 16] {
    if bits == 0 { return *a; }
    if bits >= 512 { return [0; 16]; }

    let word_shift = bits / 32;
    let bit_shift = bits % 32;

    let mut result = [0u32; 16];
    for i in word_shift..16 {
        let src = i - word_shift;
        result[i] = a[src] << bit_shift;
        if bit_shift > 0 && src > 0 {
            result[i] |= a[src - 1] >> (32 - bit_shift);
        }
    }
    result
}

/// Compare two 512-bit numbers. Returns -1, 0, or 1.
fn cmp_u512(a: &[u32; 16], b: &[u32; 16]) -> i32 {
    for i in (0..16).rev() {
        if a[i] > b[i] { return 1; }
        if a[i] < b[i] { return -1; }
    }
    0
}

/// Subtract b from a (512-bit), assuming a >= b.
fn sub_u512(a: &[u32; 16], b: &[u32; 16]) -> [u32; 16] {
    let mut result = [0u32; 16];
    let mut borrow = 0i64;
    for i in 0..16 {
        let diff = a[i] as i64 - b[i] as i64 - borrow;
        if diff < 0 {
            result[i] = (diff + (1i64 << 32)) as u32;
            borrow = 1;
        } else {
            result[i] = diff as u32;
            borrow = 0;
        }
    }
    result
}

/// Find the highest set bit position (0-indexed from LSB).
fn highest_bit_u512(a: &[u32; 16]) -> Option<usize> {
    for i in (0..16).rev() {
        if a[i] != 0 {
            let bit_in_word = 31 - a[i].leading_zeros() as usize;
            return Some(i * 32 + bit_in_word);
        }
    }
    None
}

/// Reduce a 512-bit number modulo a 256-bit prime using binary long division.
fn mod_u512(a: &[u32; 16], p: &[u32; 8]) -> [u32; 8] {
    // Extend p to 512 bits
    let mut p512 = [0u32; 16];
    for i in 0..8 {
        p512[i] = p[i];
    }

    let mut r = *a;

    // Find highest bit of p (should be around bit 255 for a 256-bit prime)
    let p_high_bit = highest_bit_u512(&p512).unwrap_or(0);

    // Binary long division
    loop {
        let r_high_bit = match highest_bit_u512(&r) {
            Some(b) => b,
            None => break, // r is zero
        };

        if r_high_bit < p_high_bit {
            break; // r < p
        }

        let shift = r_high_bit - p_high_bit;
        let p_shifted = shl_u512(&p512, shift);

        if cmp_u512(&r, &p_shifted) >= 0 {
            r = sub_u512(&r, &p_shifted);
        } else if shift > 0 {
            let p_shifted_less = shl_u512(&p512, shift - 1);
            if cmp_u512(&r, &p_shifted_less) >= 0 {
                r = sub_u512(&r, &p_shifted_less);
            }
        }
    }

    // Final comparison with p
    let mut p_cmp = [0u32; 16];
    for i in 0..8 { p_cmp[i] = p[i]; }
    while cmp_u512(&r, &p_cmp) >= 0 {
        r = sub_u512(&r, &p_cmp);
    }

    std::array::from_fn(|i| r[i])
}

fn shift_left_limbs(n: usize) -> BigInt256 {
    let mut result = [0u32; N_LIMBS];
    if n < N_LIMBS { result[n] = 1; }
    BigInt256 { limbs: result }
}

/// BN254 scalar field modulus.
pub fn modulus() -> BigInt256 {
    BigInt256 { limbs: super::MODULUS }
}

/// Baby Jubjub scalar order.
pub fn scalar_order() -> BigInt256 {
    BigInt256 { limbs: super::SCALAR_ORDER }
}

/// Trace generator for Field256 operations.
pub struct Field256TraceGen {
    pub trace: Vec<stwo::core::fields::m31::M31>,
}

impl Field256TraceGen {
    pub fn new() -> Self { Self { trace: Vec::new() } }

    pub fn append_limb(&mut self, val: u32) {
        self.trace.push(stwo::core::fields::m31::M31::from_u32_unchecked(val));
    }

    /// Append Field256 (20 limbs, no range check).
    pub fn append_field256(&mut self, val: &BigInt256) {
        for i in 0..N_LIMBS {
            self.append_limb(val.limbs[i]);
        }
    }

    /// Append Field256 with bit decomposition for range checking.
    pub fn append_field256_checked(&mut self, val: &BigInt256) {
        for i in 0..N_LIMBS {
            self.append_limb(val.limbs[i]);
            for bit in 0..LIMB_BITS {
                self.append_limb((val.limbs[i] >> bit) & 1);
            }
        }
    }

    /// Generate addition trace: result = a + b mod p.
    /// Trace: result_checked + carries(2 bits each) + reduced flag.
    pub fn gen_add(&mut self, a: &BigInt256, b: &BigInt256) -> BigInt256 {
        let p = modulus();
        let result = a.add_mod(b, &p);
        let (raw_sum, _) = a.add_no_reduce(b);
        let reduced = if raw_sum.gte(&p) { 1u32 } else { 0u32 };

        // Compute carries for: a[i] + b[i] + carry[i-1] = result[i] + reduced*p[i] + carry[i] * 2^LIMB_BITS
        let mut carries = [0u32; N_LIMBS];
        let mut prev_carry = 0i64;
        for i in 0..N_LIMBS {
            let lhs = a.limbs[i] as i64 + b.limbs[i] as i64 + prev_carry;
            let rhs_base = result.limbs[i] as i64 + (reduced as i64) * (p.limbs[i] as i64);
            let carry = (lhs - rhs_base) >> LIMB_BITS;
            carries[i] = carry as u32;
            prev_carry = carry;
        }

        self.append_field256_checked(&result);
        for c in carries {
            self.append_limb(c & 1);
            self.append_limb((c >> 1) & 1);
        }
        self.append_limb(reduced);
        result
    }

    /// Generate subtraction trace.
    pub fn gen_sub(&mut self, a: &BigInt256, b: &BigInt256) -> BigInt256 {
        let p = modulus();
        let result = a.sub_mod(b, &p);
        let borrowed = if a.lt(b) { 1u32 } else { 0u32 };

        let mut borrows = [0u32; N_LIMBS];
        let mut borrow = 0i64;
        for i in 0..N_LIMBS {
            let a_val = a.limbs[i] as i64 + if borrowed == 1 { p.limbs[i] as i64 } else { 0 };
            let diff = a_val - b.limbs[i] as i64 - borrow;
            borrows[i] = if diff < 0 { 1 } else { 0 };
            borrow = borrows[i] as i64;
        }

        self.append_field256_checked(&result);
        for bo in borrows { self.append_limb(bo); }
        self.append_limb(borrowed);
        result
    }

    /// Generate multiplication trace.
    pub fn gen_mul(&mut self, a: &BigInt256, b: &BigInt256) -> BigInt256 {
        let p = modulus();
        let result = a.mul_mod(b, &p);

        // Compute quotient q such that a*b = q*p + r
        let ab_wide = a.mul_wide(b);
        let mut q = BigInt256::zero();
        // Simplified: just output result and quotient, let constraints verify

        self.append_field256_checked(&result);
        self.append_field256(&q);

        // Append sub-products
        for i in 0..N_LIMBS {
            for j in 0..N_LIMBS {
                self.append_limb(a.limbs[i] * b.limbs[j]);
            }
        }
        for i in 0..N_LIMBS {
            for j in 0..N_LIMBS {
                self.append_limb(q.limbs[i] * p.limbs[j]);
            }
        }

        // Append carries (simplified)
        let n_product_limbs = 2 * N_LIMBS - 1;
        for _ in 0..n_product_limbs {
            self.append_limb(0); // sign
            self.append_limb(0); // lo
            self.append_limb(0); // hi
        }

        result
    }

    /// Generate inversion trace.
    pub fn gen_inv(&mut self, a: &BigInt256) -> BigInt256 {
        let p = modulus();
        let inv = a.inv_mod(&p).expect("Cannot invert zero");
        self.append_field256(&inv);
        let _ = self.gen_mul(a, &inv);
        inv
    }

    /// Generate select trace: return a if cond=0, b if cond=1.
    /// This is purely for trace generation - the constraint evaluator computes
    /// the selection algebraically without needing trace values.
    pub fn gen_select(&mut self, cond: u32, a: &BigInt256, b: &BigInt256) -> BigInt256 {
        // No trace values needed - selection is computed algebraically in constraints
        // result = a + cond * (b - a)
        if cond != 0 { *b } else { *a }
    }
}

impl Default for Field256TraceGen {
    fn default() -> Self { Self::new() }
}

/// Trace columns for addition.
pub fn add_trace_columns() -> usize {
    N_LIMBS + N_LIMBS * LIMB_BITS as usize + N_LIMBS * 2 + 1
}

/// Trace columns for multiplication.
pub fn mul_trace_columns() -> usize {
    N_LIMBS + N_LIMBS * LIMB_BITS as usize + N_LIMBS + N_LIMBS * N_LIMBS * 2 + (2 * N_LIMBS - 1) * 3
}
