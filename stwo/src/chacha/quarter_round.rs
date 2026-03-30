//! ChaCha20 quarter-round constraints.
//!
//! The quarter-round operates on 4 u32 words (a, b, c, d):
//!   a += b; d ^= a; d <<<= 16;
//!   c += d; b ^= c; b <<<= 12;
//!   a += b; d ^= a; d <<<= 8;
//!   c += d; b ^= c; b <<<= 7;
//!
//! We implement this using:
//! - Addition with carry tracking (like BLAKE)
//! - XOR via lookup tables (LogUp)
//! - Left rotation by splitting and reassembling


/// Compute a ChaCha quarter-round on 4 words.
///
/// This is a reference implementation for testing - the actual circuit
/// will use constraint evaluation.
pub fn quarter_round_native(state: &mut [u32; 4]) {
    let [a, b, c, d] = state;

    // a += b; d ^= a; d <<<= 16;
    *a = a.wrapping_add(*b);
    *d ^= *a;
    *d = d.rotate_left(16);

    // c += d; b ^= c; b <<<= 12;
    *c = c.wrapping_add(*d);
    *b ^= *c;
    *b = b.rotate_left(12);

    // a += b; d ^= a; d <<<= 8;
    *a = a.wrapping_add(*b);
    *d ^= *a;
    *d = d.rotate_left(8);

    // c += d; b ^= c; b <<<= 7;
    *c = c.wrapping_add(*d);
    *b ^= *c;
    *b = b.rotate_left(7);
}

/// Left rotate a u32 by `r` bits (native implementation for testing)
#[inline]
pub fn rotate_left(x: u32, r: u32) -> u32 {
    (x << r) | (x >> (32 - r))
}

/// XOR and left rotate: computes (a ^ b) <<< r
///
/// For the constraint system, we split each u32 into two 16-bit halves.
/// Left rotation by r (where 0 < r < 16) works as follows:
///
/// Given a = (a_h << 16) | a_l and b = (b_h << 16) | b_l
/// Let c = a ^ b = (c_h << 16) | c_l where c_h = a_h ^ b_h, c_l = a_l ^ b_l
///
/// For left rotation by r < 16:
///   c_l splits into: c_ll (low r bits) and c_lh (high 16-r bits)
///   c_h splits into: c_hl (low r bits) and c_hh (high 16-r bits)
///
///   result_l = (c_ll << (16-r)) | c_hh   (low bits of c_l go high, high bits of c_h come in low)
///   result_h = (c_hl << (16-r)) | c_lh   (low bits of c_h go high, high bits of c_l come in low)
///
/// Wait, let me reconsider. For a 32-bit left rotation by r:
///   result = (x << r) | (x >> (32-r))
///
/// If x = (h << 16) | l, and r < 16:
///   x << r = (h << (16+r)) | (l << r)
///          = (h << (16+r)) | ((l_high << r) | (l_low << r))
///   where l = (l_high << (16-r)) | l_low  (l_high is top r bits, l_low is bottom 16-r bits)
///
/// This is getting complex. Let me just implement it step by step.
pub fn xor_rotl_native(a: u32, b: u32, r: u32) -> u32 {
    (a ^ b).rotate_left(r)
}

/// Split a u32 into (low_bits, high_bits) at position r
/// Returns (x & ((1 << r) - 1), x >> r)
#[inline]
pub fn split_at(x: u32, r: u32) -> (u32, u32) {
    let mask = (1u32 << r) - 1;
    (x & mask, x >> r)
}

/// Detailed breakdown of XOR + left rotate for constraint system.
///
/// For ChaCha, we need rotations by 16, 12, 8, and 7 bits.
///
/// Rotation by 16 is special: it just swaps the two 16-bit halves.
pub fn xor_rotl16_detailed(a_l: u32, a_h: u32, b_l: u32, b_h: u32) -> (u32, u32) {
    let c_l = a_l ^ b_l;
    let c_h = a_h ^ b_h;
    // Left rotate by 16 = swap halves
    (c_h, c_l)
}

/// XOR and left rotate by r bits (0 < r < 16), showing the split structure
///
/// For left rotation by r of a 32-bit number c = (c_h << 16) | c_l:
///   rotl(c, r) = (c << r) | (c >> (32-r))
///
/// Decomposing into 16-bit halves:
///   c_l_low  = c_l & ((1 << (16-r)) - 1)  // bottom 16-r bits of c_l
///   c_l_high = c_l >> (16-r)              // top r bits of c_l
///   c_h_low  = c_h & ((1 << (16-r)) - 1)  // bottom 16-r bits of c_h
///   c_h_high = c_h >> (16-r)              // top r bits of c_h
///
///   result_l = (c_l_low << r) | c_h_high
///   result_h = (c_h_low << r) | c_l_high
pub fn xor_rotl_detailed(a_l: u32, a_h: u32, b_l: u32, b_h: u32, r: u32) -> (u32, u32) {
    assert!(r > 0 && r < 16, "r must be in (0, 16)");

    let c_l = a_l ^ b_l;
    let c_h = a_h ^ b_h;

    // Split each 16-bit half at position (16 - r)
    let c_l_low = c_l & ((1 << (16 - r)) - 1);   // bottom 16-r bits
    let c_l_high = c_l >> (16 - r);              // top r bits

    let c_h_low = c_h & ((1 << (16 - r)) - 1);   // bottom 16-r bits
    let c_h_high = c_h >> (16 - r);              // top r bits

    // Reassemble with rotation
    let result_l = (c_l_low << r) | c_h_high;
    let result_h = (c_h_low << r) | c_l_high;

    (result_l, result_h)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_quarter_round() {
        // Test vector from RFC 7539
        let mut state = [0x11111111u32, 0x01020304, 0x9b8d6f43, 0x01234567];
        quarter_round_native(&mut state);
        assert_eq!(state, [0xea2a92f4, 0xcb1cf8ce, 0x4581472e, 0x5881c4bb]);
    }

    #[test]
    fn test_xor_rotl() {
        let a = 0xAABBCCDDu32;
        let b = 0x11223344u32;

        // Test rotation by 16 (swap halves)
        let _c = a ^ b;  // 0xBB99FFFF... let me compute: 0xAA^0x11=0xBB, 0xBB^0x22=0x99, 0xCC^0x33=0xFF, 0xDD^0x44=0x99
        // Actually: 0xAABBCCDD ^ 0x11223344 = 0xBB99FF99
        assert_eq!(a ^ b, 0xBB99FF99);

        let expected_rotl16 = (a ^ b).rotate_left(16);
        let (l, h) = xor_rotl16_detailed(0xCCDD, 0xAABB, 0x3344, 0x1122);
        let actual = ((h as u32) << 16) | (l as u32);
        assert_eq!(actual, expected_rotl16);
    }

    #[test]
    fn test_xor_rotl_8() {
        let a = 0xAABBCCDDu32;
        let b = 0x11223344u32;
        let c = a ^ b;  // 0xBB99FF99

        let expected = c.rotate_left(8);  // 0x99FF99BB

        let a_l = (a & 0xFFFF) as u32;  // 0xCCDD
        let a_h = (a >> 16) as u32;      // 0xAABB
        let b_l = (b & 0xFFFF) as u32;  // 0x3344
        let b_h = (b >> 16) as u32;      // 0x1122

        let (result_l, result_h) = xor_rotl_detailed(a_l, a_h, b_l, b_h, 8);
        let actual = (result_h << 16) | result_l;

        assert_eq!(actual, expected, "rotl8: expected {:#x}, got {:#x}", expected, actual);
    }

    #[test]
    fn test_xor_rotl_12() {
        let a = 0x12345678u32;
        let b = 0x9ABCDEF0u32;
        let c = a ^ b;

        let expected = c.rotate_left(12);

        let a_l = (a & 0xFFFF) as u32;
        let a_h = (a >> 16) as u32;
        let b_l = (b & 0xFFFF) as u32;
        let b_h = (b >> 16) as u32;

        let (result_l, result_h) = xor_rotl_detailed(a_l, a_h, b_l, b_h, 12);
        let actual = (result_h << 16) | result_l;

        assert_eq!(actual, expected, "rotl12: expected {:#x}, got {:#x}", expected, actual);
    }

    #[test]
    fn test_xor_rotl_7() {
        let a = 0xDEADBEEFu32;
        let b = 0xCAFEBABEu32;
        let c = a ^ b;

        let expected = c.rotate_left(7);

        let a_l = (a & 0xFFFF) as u32;
        let a_h = (a >> 16) as u32;
        let b_l = (b & 0xFFFF) as u32;
        let b_h = (b >> 16) as u32;

        let (result_l, result_h) = xor_rotl_detailed(a_l, a_h, b_l, b_h, 7);
        let actual = (result_h << 16) | result_l;

        assert_eq!(actual, expected, "rotl7: expected {:#x}, got {:#x}", expected, actual);
    }
}
