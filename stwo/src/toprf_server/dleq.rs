//! DLEQ (Discrete Log Equality) proofs for TOPRF.
//!
//! Proves that log_G(xG) = log_H(xH) without revealing x.
//! This is used to prove the server used the correct private key.
//!
//! Based on RFC 9497 (OPRF) with cofactor clearing for small subgroup protection.

use rand::Rng;

use super::dkg::random_scalar;
use crate::babyjub::field256::gen::{modulus, scalar_order, BigInt256};
use crate::babyjub::point::gen::native as point_native;
use crate::babyjub::point::{base_point, ExtendedPointBigInt};

/// Clear cofactor by multiplying point by 8.
/// Returns None if the result is the identity (point was in small subgroup).
pub fn clear_cofactor(p: &ExtendedPointBigInt) -> Option<ExtendedPointBigInt> {
    let result = point_native::clear_cofactor(p);

    // Check if result is identity (0, 1, 0, 1)
    if result.x.is_zero()
        && result.y == BigInt256::one()
        && result.t.is_zero()
        && result.z == BigInt256::one()
    {
        None
    } else {
        Some(result)
    }
}

/// Hash points to scalar using MiMC (gnark-compatible).
///
/// This matches gnark-crypto's HashPointsToScalar which:
/// 1. For each point, writes X.Bytes() and Y.Bytes() to the hasher
/// 2. gnark-crypto's MiMC hasher LEFT-PADS each write to 32 bytes individually
/// 3. Each 32-byte padded value becomes one field element
/// 4. Result is reduced mod scalar_order for use as EC scalar
///
/// IMPORTANT: gnark's MiMC hasher pads each Write() call independently!
/// Example: if x = 31 bytes and y = 31 bytes:
/// - element1 = 0x00 || x (32 bytes)
/// - element2 = 0x00 || y (32 bytes)
/// NOT: concatenate(x, y) and chunk at 32-byte boundaries
fn hash_points_to_scalar_mimc(points: &[&ExtendedPointBigInt]) -> BigInt256 {
    use crate::babyjub::mimc_compat::mimc_hash;
    let modulus = modulus();

    // Each coordinate is independently left-padded to 32 bytes
    // This matches gnark-crypto's MiMC hasher behavior where each Write()
    // with < 32 bytes gets left-padded before becoming a field element
    let mut elements: Vec<BigInt256> = Vec::new();
    for point in points {
        let (x, y) = point.to_affine(&modulus);

        // Each coordinate becomes one element, left-padded to 32 bytes
        // to_bytes_be_trimmed gives variable-length big-endian bytes
        // from_bytes_be automatically left-pads to 32 bytes (matching gnark)
        let x_bytes = x.to_bytes_be_trimmed();
        let y_bytes = y.to_bytes_be_trimmed();

        elements.push(BigInt256::from_bytes_be(&x_bytes));
        elements.push(BigInt256::from_bytes_be(&y_bytes));
    }

    let hash = mimc_hash(&elements);

    // Reduce mod scalar_order for use as EC scalar
    // MiMC returns values in [0, field_modulus), but scalars must be in [0, scalar_order)
    let order = scalar_order();
    reduce_mod_order(&hash, &order)
}

/// Reduce a BigInt256 modulo the scalar order.
fn reduce_mod_order(val: &BigInt256, order: &BigInt256) -> BigInt256 {
    let mut result = *val;
    // Repeatedly subtract order while result >= order
    while result.cmp(order) >= 0 {
        let (diff, _) = result.sub_no_reduce(order);
        result = diff;
    }
    result
}

/// Generate a DLEQ proof using MiMC hash (gnark-compatible).
///
/// This matches gnark's ProveDLEQ function for cross-system verification.
/// NOTE: This version does NOT use cofactor clearing to match the current gnark binary.
pub fn prove_dleq_mimc<R: Rng>(
    rng: &mut R,
    x: &BigInt256,
    h: &ExtendedPointBigInt,
) -> Option<(BigInt256, BigInt256)> {
    let base = base_point();
    let order = scalar_order();

    // Compute xG = G * x
    let x_g = point_native::scalar_mul(&base, x);

    // Compute xH = H * x
    let x_h = point_native::scalar_mul(h, x);

    // Generate random v
    let v = random_scalar(rng);

    // Compute vG = G * v
    let v_g = point_native::scalar_mul(&base, &v);

    // Compute vH = H * v
    let v_h = point_native::scalar_mul(h, &v);

    // Compute challenge: c = Hash(G, xG, vG, vH, H, xH) using MiMC
    // NOTE: No cofactor clearing - matches old gnark binary
    let c = hash_points_to_scalar_mimc(&[&base, &x_g, &v_g, &v_h, h, &x_h]);

    // Compute r = v - c * x mod scalar_order
    // NOTE: No cofactor multiplication - matches old gnark binary
    let c_times_x = c.mul_mod(x, &order);
    let r = v.sub_mod(&c_times_x, &order);

    Some((c, r))
}

/// Verify a DLEQ proof using MiMC hash (gnark-compatible).
///
/// This matches gnark's VerifyDLEQ function for cross-system verification.
/// NOTE: This version does NOT use cofactor clearing to match the current gnark binary.
/// NOTE: Input c is reduced mod scalar_order to handle gnark's unreduced hash output.
pub fn verify_dleq_mimc(
    c: &BigInt256,
    r: &BigInt256,
    x_g: &ExtendedPointBigInt,
    x_h: &ExtendedPointBigInt,
    h: &ExtendedPointBigInt,
) -> bool {
    let base = base_point();
    let order = scalar_order();

    // Reduce c mod scalar_order to handle gnark's unreduced hash output
    // This ensures scalar_mul works correctly even if c > order
    let c_reduced = reduce_mod_order(c, &order);

    // Reconstruct vG = r*G + c*xG
    // NOTE: No cofactor clearing - matches old gnark binary
    let r_g = point_native::scalar_mul(&base, r);
    let c_xg = point_native::scalar_mul(x_g, &c_reduced);
    let v_g = point_native::add_points(&r_g, &c_xg);

    // Reconstruct vH = r*H + c*xH
    let r_h = point_native::scalar_mul(h, r);
    let c_xh = point_native::scalar_mul(x_h, &c_reduced);
    let v_h = point_native::add_points(&r_h, &c_xh);

    // Recompute hash using MiMC (already reduced mod order by hash_points_to_scalar_mimc)
    // NOTE: No cofactor clearing - matches old gnark binary
    let expected_c = hash_points_to_scalar_mimc(&[&base, x_g, &v_g, &v_h, h, x_h]);

    // Check reduced c == expected_c (both are now reduced mod order)
    c_reduced.limbs == expected_c.limbs
}

/// Verify a DLEQ proof using MiMC hash WITH cofactor clearing.
///
/// This matches gnark's NEW VerifyDLEQ function (with RFC 9497 cofactor clearing).
/// Use this if the gnark binary has been updated to include cofactor clearing.
pub fn verify_dleq_mimc_with_cofactor(
    c: &BigInt256,
    r: &BigInt256,
    x_g: &ExtendedPointBigInt,
    x_h: &ExtendedPointBigInt,
    h: &ExtendedPointBigInt,
) -> bool {
    let base = base_point();
    let order = scalar_order();

    // Clear cofactors (multiply by 8)
    let x_g_cleared = match clear_cofactor(x_g) {
        Some(p) => p,
        None => return false, // Point in small subgroup
    };
    let x_h_cleared = match clear_cofactor(x_h) {
        Some(p) => p,
        None => return false, // Point in small subgroup
    };

    // Reduce c mod scalar_order to handle gnark's unreduced hash output
    let c_reduced = reduce_mod_order(c, &order);

    // Reconstruct vG = r*G + c*xG_cleared
    let r_g = point_native::scalar_mul(&base, r);
    let c_xg = point_native::scalar_mul(&x_g_cleared, &c_reduced);
    let v_g = point_native::add_points(&r_g, &c_xg);

    // Reconstruct vH = r*H + c*xH_cleared
    let r_h = point_native::scalar_mul(h, r);
    let c_xh = point_native::scalar_mul(&x_h_cleared, &c_reduced);
    let v_h = point_native::add_points(&r_h, &c_xh);

    // Recompute hash using MiMC with cleared points
    let expected_c = hash_points_to_scalar_mimc(&[&base, &x_g_cleared, &v_g, &v_h, h, &x_h_cleared]);

    // Check reduced c == expected_c
    c_reduced.limbs == expected_c.limbs
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::toprf_server::dkg::random_scalar;
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;

    #[test]
    fn test_doubling_vs_scalar() {
        // Test that 2*P via double_point equals 2*P via scalar_mul
        let mut rng = ChaCha20Rng::seed_from_u64(42);
        let modulus = modulus();
        let base = base_point();

        let x = random_scalar(&mut rng);
        let p = point_native::scalar_mul(&base, &x);

        // Method 1: double_point
        let doubled = point_native::double_point(&p);

        // Method 2: scalar_mul by 2
        let two = BigInt256::from_u32(2);
        let scalar_2 = point_native::scalar_mul(&p, &two);

        // Convert to affine
        let (d_x, d_y) = doubled.to_affine(&modulus);
        let (s_x, s_y) = scalar_2.to_affine(&modulus);

        println!("double_point(P): x = {:?}", d_x.limbs);
        println!("scalar_mul(P, 2): x = {:?}", s_x.limbs);

        assert_eq!(d_x.limbs, s_x.limbs, "x coordinates should match");
        assert_eq!(d_y.limbs, s_y.limbs, "y coordinates should match");
    }

    #[test]
    fn test_8_via_doubling_vs_scalar() {
        // Test that 8*P via 3 doublings equals 8*P via scalar_mul
        let mut rng = ChaCha20Rng::seed_from_u64(42);
        let modulus = modulus();
        let base = base_point();

        let x = random_scalar(&mut rng);
        let p = point_native::scalar_mul(&base, &x);

        // Method 1: 3 doublings (clear_cofactor)
        let via_double = point_native::clear_cofactor(&p);

        // Method 2: scalar_mul by 8
        let eight = BigInt256::from_u32(8);
        let via_scalar = point_native::scalar_mul(&p, &eight);

        // Convert to affine
        let (d_x, d_y) = via_double.to_affine(&modulus);
        let (s_x, s_y) = via_scalar.to_affine(&modulus);

        println!("clear_cofactor(P) [3 doublings]: x = {:?}", d_x.limbs);
        println!("scalar_mul(P, 8): x = {:?}", s_x.limbs);

        assert_eq!(d_x.limbs, s_x.limbs, "x coordinates should match");
        assert_eq!(d_y.limbs, s_y.limbs, "y coordinates should match");
    }

    #[test]
    fn test_base_point_times_8() {
        // Test that G * 8 via scalar_mul equals 8 * G via doubling
        let modulus = modulus();
        let base = base_point();

        // Method 1: scalar_mul(G, 8)
        let eight = BigInt256::from_u32(8);
        let g_times_8 = point_native::scalar_mul(&base, &eight);

        // Method 2: clear_cofactor(G) = 8 * G
        let eight_times_g = point_native::clear_cofactor(&base);

        // Convert to affine
        let (m1_x, m1_y) = g_times_8.to_affine(&modulus);
        let (m2_x, m2_y) = eight_times_g.to_affine(&modulus);

        println!("G * 8 (scalar_mul): x = {:?}", m1_x.limbs);
        println!("8 * G (doubling): x = {:?}", m2_x.limbs);

        assert_eq!(m1_x.limbs, m2_x.limbs, "x coordinates should match");
        assert_eq!(m1_y.limbs, m2_y.limbs, "y coordinates should match");
    }

    #[test]
    fn test_mul_mod_8() {
        // Test that 8 * b mod p is correct by checking G * (8*b) = 8 * (G*b)
        let mut rng = ChaCha20Rng::seed_from_u64(42);
        let modulus = modulus();
        let base = base_point();

        let b = random_scalar(&mut rng);
        let eight = BigInt256::from_u32(8);

        // Compute 8*b using mul_mod
        let eight_b = eight.mul_mod(&b, &modulus);

        println!("b = {:?}", b.limbs);
        println!("8*b mod p = {:?}", eight_b.limbs);

        // Verify: 8*b should equal b added to itself 8 times
        let mut sum = BigInt256::zero();
        for _ in 0..8 {
            sum = sum.add_mod(&b, &modulus);
        }
        println!("b + b + ... (8 times) = {:?}", sum.limbs);

        assert_eq!(eight_b.limbs, sum.limbs, "8*b should equal 8 additions of b");
    }

    #[test]
    fn test_scalar_mul_identity() {
        // Verify scalar_mul(P, 1) = P
        let mut rng = ChaCha20Rng::seed_from_u64(42);
        let modulus = modulus();
        let base = base_point();

        let b = random_scalar(&mut rng);
        let one = BigInt256::from_u32(1);

        // G * b
        let g_b = point_native::scalar_mul(&base, &b);
        let (g_b_x, g_b_y) = g_b.to_affine(&modulus);

        // (G * b) * 1
        let g_b_times_1 = point_native::scalar_mul(&g_b, &one);
        let (gbt1_x, gbt1_y) = g_b_times_1.to_affine(&modulus);

        println!("G*b: x = {:?}", g_b_x.limbs);
        println!("(G*b)*1: x = {:?}", gbt1_x.limbs);

        assert_eq!(g_b_x.limbs, gbt1_x.limbs, "x should match");
        assert_eq!(g_b_y.limbs, gbt1_y.limbs, "y should match");
    }

    #[test]
    fn test_scalar_mul_2_vs_double() {
        // Verify scalar_mul(P, 2) = double_point(P) for P = G*b
        let mut rng = ChaCha20Rng::seed_from_u64(42);
        let modulus = modulus();
        let base = base_point();

        let b = random_scalar(&mut rng);
        let two = BigInt256::from_u32(2);

        // G * b
        let g_b = point_native::scalar_mul(&base, &b);

        // (G * b) * 2
        let g_b_times_2 = point_native::scalar_mul(&g_b, &two);
        let (t2_x, t2_y) = g_b_times_2.to_affine(&modulus);

        // double(G * b)
        let doubled = point_native::double_point(&g_b);
        let (d_x, d_y) = doubled.to_affine(&modulus);

        println!("(G*b)*2: x = {:?}", t2_x.limbs);
        println!("double(G*b): x = {:?}", d_x.limbs);

        assert_eq!(t2_x.limbs, d_x.limbs, "x should match");
        assert_eq!(t2_y.limbs, d_y.limbs, "y should match");
    }

    #[test]
    fn test_scalar_bits_for_sum() {
        // Verify that scalar_to_bits(8*b) gives proper bits that would result in 8*(G*b)
        use crate::babyjub::point::gen::{scalar_to_bits, bits_to_scalar};

        let mut rng = ChaCha20Rng::seed_from_u64(42);
        let base_modulus = modulus();
        let order = scalar_order();
        let base = base_point();

        let b = random_scalar(&mut rng);
        let eight = BigInt256::from_u32(8);
        let eight_b = eight.mul_mod(&b, &order);

        // Get bits for 8*b
        let bits_8b = scalar_to_bits(&eight_b);

        // Convert bits back to scalar
        let recovered = bits_to_scalar(&bits_8b);

        println!("8*b original: {:?}", eight_b.limbs);
        println!("8*b from bits: {:?}", recovered.limbs);

        // Check that 8*b round-trips
        assert_eq!(eight_b.limbs, recovered.limbs, "8*b should round-trip through bits");

        // Now manually compute G * (8*b) using the bits
        let mut result = ExtendedPointBigInt::identity();
        for i in (0..254).rev() {
            result = point_native::double_point(&result);
            if bits_8b[i] {
                result = point_native::add_points(&result, &base);
            }
        }
        let (manual_x, _) = result.to_affine(&base_modulus);

        // Compare with scalar_mul result
        let via_scalar_mul = point_native::scalar_mul(&base, &eight_b);
        let (sm_x, _) = via_scalar_mul.to_affine(&base_modulus);

        println!("G*(8*b) manual: {:?}", manual_x.limbs);
        println!("G*(8*b) via scalar_mul: {:?}", sm_x.limbs);

        assert_eq!(manual_x.limbs, sm_x.limbs, "Manual and scalar_mul should match");
    }

    #[test]
    fn test_scalar_associativity() {
        // Test scalar multiplication associativity: (a*b)*G = a*(b*G)
        let mut rng = ChaCha20Rng::seed_from_u64(42);
        let base_modulus = modulus();
        let order = scalar_order();
        let base = base_point();

        let a = BigInt256::from_u32(8); // Use 8 like cofactor
        let b = random_scalar(&mut rng);

        // Method 1: (a*b)*G - first compute scalar product, then multiply G
        let ab = a.mul_mod(&b, &order);
        let ab_g = point_native::scalar_mul(&base, &ab);

        // Method 2: a*(b*G) - first multiply G by b, then multiply result by a
        let b_g = point_native::scalar_mul(&base, &b);
        let a_bg = point_native::scalar_mul(&b_g, &a);

        // Also try Method 3: b*G added 8 times
        let mut acc = ExtendedPointBigInt::identity();
        for _ in 0..8 {
            acc = point_native::add_points(&acc, &b_g);
        }

        // Convert to affine
        let (m1_x, m1_y) = ab_g.to_affine(&base_modulus);
        let (m2_x, m2_y) = a_bg.to_affine(&base_modulus);
        let (m3_x, _m3_y) = acc.to_affine(&base_modulus);

        println!("(a*b)*G: x = {:?}", m1_x.limbs);
        println!("a*(b*G) via scalar_mul: x = {:?}", m2_x.limbs);
        println!("(b*G) + (b*G) + ... (8 times): x = {:?}", m3_x.limbs);
        println!("a = {:?}", a.limbs);
        println!("b = {:?}", b.limbs);
        println!("a*b mod p = {:?}", ab.limbs);

        // m2 and m3 should match (both are 8 * (b*G))
        assert_eq!(m2_x.limbs, m3_x.limbs, "scalar_mul by 8 should equal 8 additions");

        // All three should match
        assert_eq!(m1_x.limbs, m2_x.limbs, "x coordinates should match");
        assert_eq!(m1_y.limbs, m2_y.limbs, "y coordinates should match");
    }

    #[test]
    fn test_cofactor_scalar_equivalence() {
        // Test that 8*(G*x) = G*(8*x) - cofactor clearing via point doubling
        // should equal scalar multiplication by 8
        let mut rng = ChaCha20Rng::seed_from_u64(42);
        let base_modulus = modulus();
        let order = scalar_order();
        let base = base_point();

        let x = random_scalar(&mut rng);

        // Method 1: 8*(G*x) via clear_cofactor (3 doublings)
        let g_x = point_native::scalar_mul(&base, &x);
        let eight_g_x_via_double = point_native::clear_cofactor(&g_x);

        // Method 2: G*(8*x) via scalar multiplication
        let eight = BigInt256::from_u32(8);
        let eight_x = eight.mul_mod(&x, &order);
        let g_eight_x = point_native::scalar_mul(&base, &eight_x);

        // Convert to affine and compare
        let (m1_x, m1_y) = eight_g_x_via_double.to_affine(&base_modulus);
        let (m2_x, m2_y) = g_eight_x.to_affine(&base_modulus);

        println!("8*(G*x) via double: x = {:?}", m1_x.limbs);
        println!("G*(8*x) via scalar: x = {:?}", m2_x.limbs);

        assert_eq!(m1_x.limbs, m2_x.limbs, "x coordinates should match");
        assert_eq!(m1_y.limbs, m2_y.limbs, "y coordinates should match");
    }

    #[test]
    fn test_point_add_commutative() {
        // Test that (a+b)*G = a*G + b*G
        let mut rng = ChaCha20Rng::seed_from_u64(42);
        let base_modulus = modulus();
        let order = scalar_order();
        let base = base_point();

        let a = random_scalar(&mut rng);
        let b = random_scalar(&mut rng);

        // Method 1: (a+b)*G
        let a_plus_b = a.add_mod(&b, &order);
        let direct = point_native::scalar_mul(&base, &a_plus_b);

        // Method 2: a*G + b*G
        let a_g = point_native::scalar_mul(&base, &a);
        let b_g = point_native::scalar_mul(&base, &b);
        let sum = point_native::add_points(&a_g, &b_g);

        // Convert to affine and compare
        let (d_x, d_y) = direct.to_affine(&base_modulus);
        let (s_x, s_y) = sum.to_affine(&base_modulus);

        println!("(a+b)*G: x = {:?}", d_x.limbs);
        println!("a*G + b*G: x = {:?}", s_x.limbs);

        assert_eq!(d_x.limbs, s_x.limbs, "x coordinates should match");
        assert_eq!(d_y.limbs, s_y.limbs, "y coordinates should match");
    }

    #[test]
    fn test_point_arithmetic_relationship() {
        // Test that r*G + c*(8*G*x) = v*G when r = v - c*8*x
        let mut rng = ChaCha20Rng::seed_from_u64(42);
        let base_modulus = modulus();
        let order = scalar_order();
        let base = base_point();

        let x = random_scalar(&mut rng);
        let c = random_scalar(&mut rng);
        let v = random_scalar(&mut rng);

        // Compute 8*x
        let eight = BigInt256::from_u32(8);
        let eight_x = eight.mul_mod(&x, &order);

        // r = v - c*8*x
        let c_times_8x = c.mul_mod(&eight_x, &order);
        let r = v.sub_mod(&c_times_8x, &order);

        // Verify: r + c*8*x = v
        let check = r.add_mod(&c_times_8x, &order);
        assert_eq!(check.limbs, v.limbs, "r + c*8*x should equal v");

        // Method 1: v*G
        let v_g = point_native::scalar_mul(&base, &v);

        // Method 2: r*G + c*(8*G*x)
        // First: G*x
        let g_x = point_native::scalar_mul(&base, &x);
        // Then: 8*(G*x)
        let eight_g_x = point_native::clear_cofactor(&g_x);
        // Then: c*(8*G*x)
        let c_eight_g_x = point_native::scalar_mul(&eight_g_x, &c);
        // Then: r*G
        let r_g = point_native::scalar_mul(&base, &r);
        // Finally: r*G + c*(8*G*x)
        let reconstructed = point_native::add_points(&r_g, &c_eight_g_x);

        // Convert to affine and compare
        let (vg_x, vg_y) = v_g.to_affine(&base_modulus);
        let (rec_x, rec_y) = reconstructed.to_affine(&base_modulus);

        println!("v*G: x = {:?}", vg_x.limbs);
        println!("r*G + c*(8*G*x): x = {:?}", rec_x.limbs);

        // These should be equal
        assert_eq!(vg_x.limbs, rec_x.limbs, "x coordinates should match");
        assert_eq!(vg_y.limbs, rec_y.limbs, "y coordinates should match");
    }

    #[test]
    fn test_clear_cofactor() {
        // Clear cofactor on base point
        let base = base_point();

        let cleared = clear_cofactor(&base);
        assert!(cleared.is_some());

        // Result should not be identity
        let result = cleared.unwrap();
        assert!(!result.x.is_zero() || result.y != BigInt256::one());
    }

    #[test]
    fn test_prove_verify_dleq_mimc() {
        let mut rng = ChaCha20Rng::seed_from_u64(12345);

        // Generate a random secret
        let x = random_scalar(&mut rng);
        println!("x = {:?}", x.limbs);

        // Use a random point H (would be client's masked point in practice)
        let h_scalar = random_scalar(&mut rng);
        let base = base_point();
        let h = point_native::scalar_mul(&base, &h_scalar);
        println!("h.x = {:?}", h.x.limbs);

        // Compute xG and xH
        let x_g = point_native::scalar_mul(&base, &x);
        let x_h = point_native::scalar_mul(&h, &x);
        println!("x_g.x = {:?}", x_g.x.limbs);
        println!("x_h.x = {:?}", x_h.x.limbs);

        // Generate DLEQ proof with MiMC
        let proof = prove_dleq_mimc(&mut rng, &x, &h);
        assert!(proof.is_some());

        let (c, r) = proof.unwrap();
        println!("c (MiMC) = {:?}", c.limbs);
        println!("r (MiMC) = {:?}", r.limbs);

        // Verify proof with MiMC
        let valid = verify_dleq_mimc(&c, &r, &x_g, &x_h, &h);
        println!("valid (MiMC) = {}", valid);
        assert!(valid, "MiMC DLEQ proof should be valid");
    }

}

    #[test]
    fn test_dleq_mimc_roundtrip() {
        // Test that c,r survive hex encoding/decoding (like WASM API does)
        use rand::SeedableRng;
        use rand_chacha::ChaCha20Rng;
        use crate::babyjub::point::{base_point, ExtendedPointBigInt};
        use crate::babyjub::point::gen::native as point_native;
        use crate::babyjub::field256::gen::{modulus, BigInt256};
        
        let mut rng = ChaCha20Rng::seed_from_u64(42);
        let p = modulus();
        
        // Generate test values
        let x = random_scalar(&mut rng);
        let g = base_point();
        let h_scalar = random_scalar(&mut rng);
        let h = point_native::scalar_mul(&g, &h_scalar);
        
        // Prove
        let (c, r) = prove_dleq_mimc(&mut rng, &x, &h).expect("prove failed");
        
        // Simulate WASM round-trip: to_bytes_be_trimmed -> hex -> from_bytes_be
        let c_hex = hex::encode(c.to_bytes_be_trimmed());
        let r_hex = hex::encode(r.to_bytes_be_trimmed());
        
        let c_bytes = hex::decode(&c_hex).unwrap();
        let r_bytes = hex::decode(&r_hex).unwrap();
        
        let c2 = BigInt256::from_bytes_be(&c_bytes);
        let r2 = BigInt256::from_bytes_be(&r_bytes);
        
        println!("c original: {:?}", c.limbs);
        println!("c after roundtrip: {:?}", c2.limbs);
        println!("r original: {:?}", r.limbs);
        println!("r after roundtrip: {:?}", r2.limbs);
        
        assert_eq!(c.limbs, c2.limbs, "c changed after roundtrip");
        assert_eq!(r.limbs, r2.limbs, "r changed after roundtrip");
        
        // Compute the points needed for verification
        let x_g = point_native::scalar_mul(&g, &x);
        let x_h = point_native::scalar_mul(&h, &x);
        
        // Verify with original values
        let valid1 = verify_dleq_mimc(&c, &r, &x_g, &x_h, &h);
        println!("Valid with original c,r: {}", valid1);
        
        // Verify with roundtripped values
        let valid2 = verify_dleq_mimc(&c2, &r2, &x_g, &x_h, &h);
        println!("Valid with roundtripped c,r: {}", valid2);
        
        assert!(valid1, "Original verification should pass");
        assert!(valid2, "Roundtrip verification should pass");
    }

    #[test]
    fn test_dleq_mimc_full_wasm_flow() {
        // Simulate the complete WASM API flow
        use rand::SeedableRng;
        use rand_chacha::ChaCha20Rng;
        use crate::babyjub::point::{base_point, ExtendedPointBigInt};
        use crate::babyjub::point::gen::native as point_native;
        use crate::babyjub::field256::gen::{modulus, BigInt256};
        use crate::toprf_server::{Share, evaluate_oprf_mimc, finalize_toprf_mimc, OPRFResponse};
        
        let mut rng = ChaCha20Rng::seed_from_u64(42);
        let p = modulus();
        
        // Generate a share (like toprf_generate_keys)
        let private_key = random_scalar(&mut rng);
        let g = base_point();
        let public_key = point_native::scalar_mul(&g, &private_key);
        
        let share = Share {
            index: 1,
            private_key: private_key.clone(),
            public_key: public_key.clone(),
        };
        
        // Create a masked request (like toprf_create_request)
        let request_scalar = random_scalar(&mut rng);
        let masked_request = point_native::scalar_mul(&g, &request_scalar);
        
        // Evaluate (like toprf_evaluate)
        let response = evaluate_oprf_mimc(&mut rng, &share, &masked_request).expect("eval failed");
        
        // Now simulate the WASM serialization/deserialization:
        // 1. Serialize response (like toprf_evaluate does)
        let public_key_bytes = public_key.to_bytes_gnark(&p);
        let evaluated_bytes = response.evaluated_point.to_bytes_gnark(&p);
        let c_hex = hex::encode(response.c.to_bytes_be_trimmed());
        let r_hex = hex::encode(response.r.to_bytes_be_trimmed());
        
        // 2. Deserialize (like toprf_finalize does)
        let public_key_2 = ExtendedPointBigInt::from_bytes_gnark(&public_key_bytes, &p).unwrap();
        let evaluated_2 = ExtendedPointBigInt::from_bytes_gnark(&evaluated_bytes, &p).unwrap();
        let c_2 = BigInt256::from_bytes_be(&hex::decode(&c_hex).unwrap());
        let r_2 = BigInt256::from_bytes_be(&hex::decode(&r_hex).unwrap());
        
        let masked_request_bytes = masked_request.to_bytes_gnark(&p);
        let masked_request_2 = ExtendedPointBigInt::from_bytes_gnark(&masked_request_bytes, &p).unwrap();
        
        // Verify directly with deserialized values
        let valid = verify_dleq_mimc(&c_2, &r_2, &public_key_2, &evaluated_2, &masked_request_2);
        println!("WASM-style verification: {}", valid);
        
        // Compare original vs deserialized public keys
        let (pk_x, pk_y) = public_key.to_affine(&p);
        let (pk2_x, pk2_y) = public_key_2.to_affine(&p);
        println!("Public key X match: {}", pk_x == pk2_x);
        println!("Public key Y match: {}", pk_y == pk2_y);
        
        // Compare original vs deserialized evaluated points
        let (ev_x, ev_y) = response.evaluated_point.to_affine(&p);
        let (ev2_x, ev2_y) = evaluated_2.to_affine(&p);
        println!("Evaluated X match: {}", ev_x == ev2_x);
        println!("Evaluated Y match: {}", ev_y == ev2_y);
        
        // Compare masked request
        let (mr_x, mr_y) = masked_request.to_affine(&p);
        let (mr2_x, mr2_y) = masked_request_2.to_affine(&p);
        println!("Masked request X match: {}", mr_x == mr2_x);
        println!("Masked request Y match: {}", mr_y == mr2_y);
        
        assert!(valid, "WASM-style verification should pass");
    }

    #[test]
    fn test_wasm_api_e2e_flow() {
        // Exactly mimics the WASM API flow from JS tests
        use rand::SeedableRng;
        use rand_chacha::ChaCha20Rng;
        use crate::babyjub::point::{base_point, ExtendedPointBigInt};
        use crate::babyjub::point::gen::native as point_native;
        use crate::babyjub::field256::gen::{modulus, scalar_order, BigInt256};
        use crate::toprf_server::{Share, OPRFResponse};
        use crate::toprf_server::eval::{evaluate_oprf_mimc, finalize_toprf_mimc, hash_to_point_mimc, mask_point};
        use crate::toprf_server::dkg::random_scalar;
        
        let mut rng = ChaCha20Rng::seed_from_u64(42);
        let p = modulus();
        let order = scalar_order();
        
        // === Step 1: toprf_generate_keys ===
        let private_key = random_scalar(&mut rng);
        let public_key = point_native::scalar_mul(&base_point(), &private_key);
        
        // Serialize like WASM does
        let private_key_hex = hex::encode(private_key.to_bytes_be_trimmed());
        let public_key_bytes = public_key.to_bytes_gnark(&p);
        let public_key_hex = hex::encode(&public_key_bytes);
        
        // === Step 2: toprf_create_request ===
        let secret_data = [
            BigInt256::from_u32(123),
            BigInt256::from_u32(456),
        ];
        let domain_sep = BigInt256::from_u32(1);
        let data_point = hash_to_point_mimc(&secret_data, &domain_sep);
        let mask = random_scalar(&mut rng);
        let masked_request = mask_point(&data_point, &mask);
        
        // Serialize like WASM does
        let mask_hex = hex::encode(mask.to_bytes_be_trimmed());
        let masked_data_hex = hex::encode(masked_request.to_bytes_gnark(&p));
        
        // === Step 3: toprf_evaluate ===
        // Deserialize (like WASM API does)
        let private_key_in = BigInt256::from_bytes_be(&hex::decode(&private_key_hex).unwrap());
        let masked_request_in = ExtendedPointBigInt::from_bytes_gnark(
            &hex::decode(&masked_data_hex).unwrap(), &p
        ).unwrap();
        
        // Derive public key from private key (like WASM does when publicKey is empty)
        let public_key_derived = point_native::scalar_mul(&base_point(), &private_key_in);
        
        let share = Share {
            index: 1,
            private_key: private_key_in.clone(),
            public_key: public_key_derived.clone(),
        };
        
        let response = evaluate_oprf_mimc(&mut rng, &share, &masked_request_in).unwrap();
        
        // Serialize response (like WASM does)
        let public_key_share_hex = hex::encode(share.public_key.to_bytes_gnark(&p));
        let evaluated_hex = hex::encode(response.evaluated_point.to_bytes_gnark(&p));
        let c_hex = hex::encode(response.c.to_bytes_be_trimmed());
        let r_hex = hex::encode(response.r.to_bytes_be_trimmed());
        
        println!("Evaluate output:");
        println!("  public_key_share_hex: {}", &public_key_share_hex);
        println!("  evaluated_hex: {}", &evaluated_hex);
        println!("  c_hex: {}", &c_hex);
        println!("  r_hex: {}", &r_hex);
        
        // === Step 4: toprf_finalize ===
        // Deserialize (like WASM API does)
        let mask_in = BigInt256::from_bytes_be(&hex::decode(&mask_hex).unwrap());
        let masked_request_fin = ExtendedPointBigInt::from_bytes_gnark(
            &hex::decode(&masked_data_hex).unwrap(), &p
        ).unwrap();
        
        // Here's the key difference: finalize uses publicKeyShare from JS, 
        // not from evaluate response!
        // In JS tests, this comes from keys.shares[0].publicKey
        let public_key_share_fin = ExtendedPointBigInt::from_bytes_gnark(
            &hex::decode(&public_key_hex).unwrap(), &p  // From generateThresholdKeys
        ).unwrap();
        let evaluated_fin = ExtendedPointBigInt::from_bytes_gnark(
            &hex::decode(&evaluated_hex).unwrap(), &p
        ).unwrap();
        let c_fin = BigInt256::from_bytes_be(&hex::decode(&c_hex).unwrap());
        let r_fin = BigInt256::from_bytes_be(&hex::decode(&r_hex).unwrap());
        
        // Compare public keys
        let (orig_x, orig_y) = public_key.to_affine(&p);
        let (der_x, der_y) = public_key_derived.to_affine(&p);
        let (fin_x, fin_y) = public_key_share_fin.to_affine(&p);
        
        println!("\nPublic key comparison:");
        println!("  Original X: {:?}", orig_x.limbs);
        println!("  Derived X:  {:?}", der_x.limbs);
        println!("  From hex X: {:?}", fin_x.limbs);
        println!("  Match: orig==der={}, orig==fin={}", 
            orig_x.limbs == der_x.limbs, orig_x.limbs == fin_x.limbs);
        
        // Now verify manually
        let valid = verify_dleq_mimc(
            &c_fin, &r_fin, 
            &public_key_share_fin,  // This is what toprf_finalize uses
            &evaluated_fin, 
            &masked_request_fin
        );
        println!("\nManual verification with public_key_hex: {}", valid);
        
        // Also try with derived public key
        let valid2 = verify_dleq_mimc(
            &c_fin, &r_fin,
            &public_key_derived,  // This is what evaluate used
            &evaluated_fin,
            &masked_request_fin
        );
        println!("Manual verification with derived public_key: {}", valid2);
        
        // Now call finalize_toprf_mimc
        let responses = vec![OPRFResponse {
            evaluated_point: evaluated_fin.clone(),
            c: c_fin.clone(),
            r: r_fin.clone(),
        }];
        
        let result = finalize_toprf_mimc(
            &[1],
            &responses,
            &[public_key_share_fin],  // Using from generateThresholdKeys
            &masked_request_fin,
            &secret_data,
            &mask_in,
        );
        
        println!("\nfinalize_toprf_mimc result: {}", result.is_some());
        assert!(result.is_some(), "Finalize should succeed");
    }
    #[test]
    fn test_debug_prove_verify_values() {
        use rand::SeedableRng;
        use rand_chacha::ChaCha20Rng;
        use crate::babyjub::point::{base_point, ExtendedPointBigInt};
        use crate::babyjub::point::gen::native as point_native;
        use crate::babyjub::field256::gen::{modulus, scalar_order, BigInt256};
        use crate::toprf_server::dkg::random_scalar;
        use crate::babyjub::mimc_compat::mimc_hash;
        
        let mut rng = ChaCha20Rng::seed_from_u64(42);
        let p = modulus();
        let order = scalar_order();
        
        // Setup similar to e2e test
        let private_key = random_scalar(&mut rng);
        let base = base_point();
        let public_key = point_native::scalar_mul(&base, &private_key);
        
        let request_scalar = random_scalar(&mut rng);
        let masked_request = point_native::scalar_mul(&base, &request_scalar);
        
        // === PROVE ===
        let x = &private_key;
        let h = &masked_request;
        
        let x_g_prove = point_native::scalar_mul(&base, x);
        let x_h_prove = point_native::scalar_mul(h, x);
        let x_g_cleared_prove = point_native::clear_cofactor(&x_g_prove);
        let x_h_cleared_prove = point_native::clear_cofactor(&x_h_prove);
        
        let v = random_scalar(&mut rng);
        let v_g_prove = point_native::scalar_mul(&base, &v);
        let v_h_prove = point_native::scalar_mul(h, &v);
        
        // Hash for c
        fn hash_points(points: &[&ExtendedPointBigInt]) -> BigInt256 {
            let p = modulus();
            let mut byte_stream: Vec<u8> = Vec::new();
            for point in points {
                let (x, y) = point.to_affine(&p);
                byte_stream.extend_from_slice(&x.to_bytes_be_trimmed());
                byte_stream.extend_from_slice(&y.to_bytes_be_trimmed());
            }
            let mut elements: Vec<BigInt256> = Vec::new();
            let mut offset = 0;
            while offset < byte_stream.len() {
                let chunk_len = (byte_stream.len() - offset).min(32);
                let chunk = &byte_stream[offset..offset + chunk_len];
                let mut padded = [0u8; 32];
                padded[32 - chunk_len..].copy_from_slice(chunk);
                elements.push(BigInt256::from_bytes_be(&padded));
                offset += 32;
            }
            mimc_hash(&elements)
        }
        
        let c = hash_points(&[&base, &x_g_cleared_prove, &v_g_prove, &v_h_prove, h, &x_h_cleared_prove]);
        
        println!("PROVE:");
        let (xg_x, _) = x_g_cleared_prove.to_affine(&p);
        let (xh_x, _) = x_h_cleared_prove.to_affine(&p);
        let (vg_x, _) = v_g_prove.to_affine(&p);
        let (vh_x, _) = v_h_prove.to_affine(&p);
        let (h_x, _) = h.to_affine(&p);
        println!("  x_g_cleared.x = {:?}", xg_x.limbs);
        println!("  x_h_cleared.x = {:?}", xh_x.limbs);
        println!("  v_g.x = {:?}", vg_x.limbs);
        println!("  v_h.x = {:?}", vh_x.limbs);
        println!("  h.x = {:?}", h_x.limbs);
        println!("  c = {:?}", c.limbs);
        
        // Compute r
        let cofactor_x = {
            let cofactor = BigInt256::from_u32(8);
            x.mul_mod(&cofactor, &order)
        };
        let c_times_8x = c.mul_mod(&cofactor_x, &order);
        let r = v.sub_mod(&c_times_8x, &order);
        
        // === VERIFY ===
        let verify_x_g = &x_g_prove;  // In verify, this is the input x_g
        let verify_x_h = &x_h_prove;  // In verify, this is the input x_h
        
        let verify_x_g_cleared = point_native::clear_cofactor(verify_x_g);
        let verify_x_h_cleared = point_native::clear_cofactor(verify_x_h);
        
        // Reconstruct v_g = r*G + c*x_g_cleared
        let r_g = point_native::scalar_mul(&base, &r);
        let c_xg = point_native::scalar_mul(&verify_x_g_cleared, &c);
        let verify_v_g = point_native::add_points(&r_g, &c_xg);
        
        // Reconstruct v_h = r*H + c*x_h_cleared
        let r_h = point_native::scalar_mul(h, &r);
        let c_xh = point_native::scalar_mul(&verify_x_h_cleared, &c);
        let verify_v_h = point_native::add_points(&r_h, &c_xh);
        
        println!("\nVERIFY:");
        let (vxg_x, _) = verify_x_g_cleared.to_affine(&p);
        let (vxh_x, _) = verify_x_h_cleared.to_affine(&p);
        let (vvg_x, _) = verify_v_g.to_affine(&p);
        let (vvh_x, _) = verify_v_h.to_affine(&p);
        println!("  x_g_cleared.x = {:?}", vxg_x.limbs);
        println!("  x_h_cleared.x = {:?}", vxh_x.limbs);
        println!("  v_g.x = {:?}", vvg_x.limbs);
        println!("  v_h.x = {:?}", vvh_x.limbs);
        
        println!("\nCOMPARE:");
        println!("  v_g match: {}", vg_x.limbs == vvg_x.limbs);
        println!("  v_h match: {}", vh_x.limbs == vvh_x.limbs);
        
        let expected_c = hash_points(&[&base, &verify_x_g_cleared, &verify_v_g, &verify_v_h, h, &verify_x_h_cleared]);
        println!("  expected_c = {:?}", expected_c.limbs);
        println!("  c == expected_c: {}", c.limbs == expected_c.limbs);
    }

    #[test]
    fn test_evaluate_oprf_mimc_debug() {
        use rand::SeedableRng;
        use rand_chacha::ChaCha20Rng;
        use crate::babyjub::point::{base_point, ExtendedPointBigInt};
        use crate::babyjub::point::gen::native as point_native;
        use crate::babyjub::field256::gen::{modulus, BigInt256};
        use crate::toprf_server::{Share, OPRFResponse};
        use crate::toprf_server::eval::evaluate_oprf_mimc;
        use crate::toprf_server::dkg::random_scalar;
        
        let mut rng = ChaCha20Rng::seed_from_u64(42);
        let p = modulus();
        
        // Create share
        let private_key = random_scalar(&mut rng);
        let public_key = point_native::scalar_mul(&base_point(), &private_key);
        let share = Share {
            index: 1,
            private_key: private_key.clone(),
            public_key: public_key.clone(),
        };
        
        // Create masked request
        let request_scalar = random_scalar(&mut rng);
        let masked_request = point_native::scalar_mul(&base_point(), &request_scalar);
        
        println!("Before evaluate:");
        let (pub_x, _) = public_key.to_affine(&p);
        let (req_x, _) = masked_request.to_affine(&p);
        println!("  public_key.x = {:?}", pub_x.limbs);
        println!("  masked_request.x = {:?}", req_x.limbs);
        
        // Evaluate
        let response = evaluate_oprf_mimc(&mut rng, &share, &masked_request).unwrap();
        
        println!("\nAfter evaluate:");
        let (eval_x, _) = response.evaluated_point.to_affine(&p);
        println!("  evaluated_point.x = {:?}", eval_x.limbs);
        println!("  c = {:?}", response.c.limbs);
        println!("  r = {:?}", response.r.limbs);
        
        // Now verify directly (not through finalize)
        let valid = verify_dleq_mimc(
            &response.c,
            &response.r,
            &share.public_key,
            &response.evaluated_point,
            &masked_request,
        );
        println!("\nDirect verify result: {}", valid);
        
        // Check what evaluate_oprf_mimc produced vs what prove_dleq_mimc would produce
        // In evaluate_oprf_mimc: evaluated_point = masked_request * private_key
        let expected_eval = point_native::scalar_mul(&masked_request, &private_key);
        let (expected_x, _) = expected_eval.to_affine(&p);
        println!("\nExpected evaluated (req * priv): {:?}", expected_x.limbs);
        println!("Match: {}", expected_x.limbs == eval_x.limbs);
        
        assert!(valid, "Direct verification should pass");
    }

    #[test]
    fn test_evaluate_with_hex_roundtrip() {
        use rand::SeedableRng;
        use rand_chacha::ChaCha20Rng;
        use crate::babyjub::point::{base_point, ExtendedPointBigInt};
        use crate::babyjub::point::gen::native as point_native;
        use crate::babyjub::field256::gen::{modulus, BigInt256};
        use crate::toprf_server::{Share};
        use crate::toprf_server::eval::evaluate_oprf_mimc;
        use crate::toprf_server::dkg::random_scalar;
        
        let mut rng = ChaCha20Rng::seed_from_u64(42);
        let p = modulus();
        
        // Create share
        let private_key = random_scalar(&mut rng);
        let public_key = point_native::scalar_mul(&base_point(), &private_key);
        let share = Share {
            index: 1,
            private_key: private_key.clone(),
            public_key: public_key.clone(),
        };
        
        // Create masked request
        let request_scalar = random_scalar(&mut rng);
        let masked_request = point_native::scalar_mul(&base_point(), &request_scalar);
        
        // Evaluate
        let response = evaluate_oprf_mimc(&mut rng, &share, &masked_request).unwrap();
        
        // Direct verify (should pass)
        let direct_valid = verify_dleq_mimc(
            &response.c,
            &response.r,
            &share.public_key,
            &response.evaluated_point,
            &masked_request,
        );
        println!("Direct verify: {}", direct_valid);
        
        // Now do hex roundtrip like WASM API
        let public_key_hex = hex::encode(share.public_key.to_bytes_gnark(&p));
        let evaluated_hex = hex::encode(response.evaluated_point.to_bytes_gnark(&p));
        let masked_request_hex = hex::encode(masked_request.to_bytes_gnark(&p));
        let c_hex = hex::encode(response.c.to_bytes_be_trimmed());
        let r_hex = hex::encode(response.r.to_bytes_be_trimmed());
        
        println!("\nHex values:");
        println!("  public_key_hex: {}", &public_key_hex);
        println!("  evaluated_hex: {}", &evaluated_hex);
        println!("  masked_request_hex: {}", &masked_request_hex);
        println!("  c_hex: {}", &c_hex);
        println!("  r_hex: {}", &r_hex);
        
        // Deserialize
        let public_key_2 = ExtendedPointBigInt::from_bytes_gnark(
            &hex::decode(&public_key_hex).unwrap(), &p
        ).unwrap();
        let evaluated_2 = ExtendedPointBigInt::from_bytes_gnark(
            &hex::decode(&evaluated_hex).unwrap(), &p
        ).unwrap();
        let masked_request_2 = ExtendedPointBigInt::from_bytes_gnark(
            &hex::decode(&masked_request_hex).unwrap(), &p
        ).unwrap();
        let c_2 = BigInt256::from_bytes_be(&hex::decode(&c_hex).unwrap());
        let r_2 = BigInt256::from_bytes_be(&hex::decode(&r_hex).unwrap());
        
        // Compare
        let (orig_pk_x, _) = share.public_key.to_affine(&p);
        let (rt_pk_x, _) = public_key_2.to_affine(&p);
        println!("\nPublic key match: {}", orig_pk_x.limbs == rt_pk_x.limbs);
        
        let (orig_ev_x, _) = response.evaluated_point.to_affine(&p);
        let (rt_ev_x, _) = evaluated_2.to_affine(&p);
        println!("Evaluated match: {}", orig_ev_x.limbs == rt_ev_x.limbs);
        
        let (orig_mr_x, _) = masked_request.to_affine(&p);
        let (rt_mr_x, _) = masked_request_2.to_affine(&p);
        println!("Masked request match: {}", orig_mr_x.limbs == rt_mr_x.limbs);
        
        println!("c match: {}", response.c.limbs == c_2.limbs);
        println!("r match: {}", response.r.limbs == r_2.limbs);
        
        // Verify with roundtripped values
        let rt_valid = verify_dleq_mimc(
            &c_2,
            &r_2,
            &public_key_2,
            &evaluated_2,
            &masked_request_2,
        );
        println!("\nRoundtrip verify: {}", rt_valid);
        
        assert!(rt_valid, "Roundtrip verification should pass");
    }

    #[test]
    fn test_wasm_debug_detailed() {
        use rand::SeedableRng;
        use rand_chacha::ChaCha20Rng;
        use crate::babyjub::point::{base_point, ExtendedPointBigInt};
        use crate::babyjub::point::gen::native as point_native;
        use crate::babyjub::field256::gen::{modulus, scalar_order, BigInt256};
        use crate::toprf_server::{Share};
        use crate::toprf_server::eval::{evaluate_oprf_mimc, hash_to_point_mimc, mask_point};
        use crate::toprf_server::dkg::random_scalar;
        use crate::babyjub::mimc_compat::mimc_hash;
        
        let mut rng = ChaCha20Rng::seed_from_u64(42);
        let p = modulus();
        let order = scalar_order();
        
        // Create share like WASM API
        let private_key = random_scalar(&mut rng);
        let public_key = point_native::scalar_mul(&base_point(), &private_key);
        let share = Share {
            index: 1,
            private_key: private_key.clone(),
            public_key: public_key.clone(),
        };
        
        // Create masked request like WASM API (using hash_to_point_mimc)
        let secret_data = [
            BigInt256::from_u32(123),
            BigInt256::from_u32(456),
        ];
        let domain_sep = BigInt256::from_u32(1);
        let data_point = hash_to_point_mimc(&secret_data, &domain_sep);
        let mask = random_scalar(&mut rng);
        let masked_request = mask_point(&data_point, &mask);
        
        println!("Input points:");
        let (pk_x, pk_y) = public_key.to_affine(&p);
        let (mr_x, mr_y) = masked_request.to_affine(&p);
        println!("  public_key = ({:?}, {:?})", pk_x.limbs, pk_y.limbs);
        println!("  masked_request = ({:?}, {:?})", mr_x.limbs, mr_y.limbs);
        
        // Evaluate
        let response = evaluate_oprf_mimc(&mut rng, &share, &masked_request).unwrap();
        
        println!("\nResponse:");
        let (ev_x, ev_y) = response.evaluated_point.to_affine(&p);
        println!("  evaluated = ({:?}, {:?})", ev_x.limbs, ev_y.limbs);
        println!("  c = {:?}", response.c.limbs);
        println!("  r = {:?}", response.r.limbs);
        
        // Direct verification (without hex roundtrip)
        let valid_direct = verify_dleq_mimc(
            &response.c,
            &response.r,
            &share.public_key,
            &response.evaluated_point,
            &masked_request,
        );
        println!("\nDirect verification: {}", valid_direct);
        
        // Manual verification with debug
        println!("\nManual verification:");
        let base = base_point();
        
        // Clear cofactors
        let x_g_cleared = point_native::clear_cofactor(&share.public_key);
        let x_h_cleared = point_native::clear_cofactor(&response.evaluated_point);
        
        let (xgc_x, _) = x_g_cleared.to_affine(&p);
        let (xhc_x, _) = x_h_cleared.to_affine(&p);
        println!("  x_g_cleared.x = {:?}", xgc_x.limbs);
        println!("  x_h_cleared.x = {:?}", xhc_x.limbs);
        
        // Reconstruct v_g = r*G + c*x_g_cleared
        let r_g = point_native::scalar_mul(&base, &response.r);
        let c_xg = point_native::scalar_mul(&x_g_cleared, &response.c);
        let v_g = point_native::add_points(&r_g, &c_xg);
        
        // Reconstruct v_h = r*H + c*x_h_cleared
        let r_h = point_native::scalar_mul(&masked_request, &response.r);
        let c_xh = point_native::scalar_mul(&x_h_cleared, &response.c);
        let v_h = point_native::add_points(&r_h, &c_xh);
        
        let (vg_x, _) = v_g.to_affine(&p);
        let (vh_x, _) = v_h.to_affine(&p);
        println!("  reconstructed v_g.x = {:?}", vg_x.limbs);
        println!("  reconstructed v_h.x = {:?}", vh_x.limbs);
        
        // Recompute hash
        fn hash_pts(points: &[&ExtendedPointBigInt]) -> BigInt256 {
            let p = modulus();
            let mut byte_stream: Vec<u8> = Vec::new();
            for point in points {
                let (x, y) = point.to_affine(&p);
                byte_stream.extend_from_slice(&x.to_bytes_be_trimmed());
                byte_stream.extend_from_slice(&y.to_bytes_be_trimmed());
            }
            let mut elements: Vec<BigInt256> = Vec::new();
            let mut offset = 0;
            while offset < byte_stream.len() {
                let chunk_len = (byte_stream.len() - offset).min(32);
                let chunk = &byte_stream[offset..offset + chunk_len];
                let mut padded = [0u8; 32];
                padded[32 - chunk_len..].copy_from_slice(chunk);
                elements.push(BigInt256::from_bytes_be(&padded));
                offset += 32;
            }
            mimc_hash(&elements)
        }
        
        let expected_c = hash_pts(&[&base, &x_g_cleared, &v_g, &v_h, &masked_request, &x_h_cleared]);
        println!("  expected_c = {:?}", expected_c.limbs);
        println!("  actual c = {:?}", response.c.limbs);
        println!("  match: {}", expected_c.limbs == response.c.limbs);
        
        assert!(valid_direct, "Direct verification should pass");
    }

    #[test]
    fn test_prove_internal_values() {
        // Check what prove_dleq_mimc computes internally
        use rand::SeedableRng;
        use rand_chacha::ChaCha20Rng;
        use crate::babyjub::point::{base_point, ExtendedPointBigInt};
        use crate::babyjub::point::gen::native as point_native;
        use crate::babyjub::field256::gen::{modulus, BigInt256};
        use crate::toprf_server::{Share};
        use crate::toprf_server::eval::{hash_to_point_mimc, mask_point};
        use crate::toprf_server::dkg::random_scalar;
        
        let mut rng = ChaCha20Rng::seed_from_u64(42);
        let p = modulus();
        
        // Create share
        let private_key = random_scalar(&mut rng);
        let share = Share {
            index: 1,
            private_key: private_key.clone(),
            public_key: point_native::scalar_mul(&base_point(), &private_key),
        };
        
        // Create masked request
        let secret_data = [
            BigInt256::from_u32(123),
            BigInt256::from_u32(456),
        ];
        let domain_sep = BigInt256::from_u32(1);
        let data_point = hash_to_point_mimc(&secret_data, &domain_sep);
        let mask = random_scalar(&mut rng);
        let masked_request = mask_point(&data_point, &mask);
        
        // What evaluate_oprf_mimc computes for evaluated_point
        let evaluated_from_eval = point_native::scalar_mul(&masked_request, &share.private_key);
        
        // What prove_dleq_mimc computes internally
        // In prove: x_h = scalar_mul(h, x) where h = masked_request, x = private_key
        let x_h_from_prove = point_native::scalar_mul(&masked_request, &share.private_key);
        
        let (ev_x, _) = evaluated_from_eval.to_affine(&p);
        let (xh_x, _) = x_h_from_prove.to_affine(&p);
        
        println!("evaluated_from_eval.x = {:?}", ev_x.limbs);
        println!("x_h_from_prove.x = {:?}", xh_x.limbs);
        println!("Match: {}", ev_x.limbs == xh_x.limbs);
        
        // Now also check x_g
        let x_g_from_prove = point_native::scalar_mul(&base_point(), &share.private_key);
        let (xg_x, _) = x_g_from_prove.to_affine(&p);
        let (pk_x, _) = share.public_key.to_affine(&p);
        
        println!("\nx_g_from_prove.x = {:?}", xg_x.limbs);
        println!("public_key.x = {:?}", pk_x.limbs);
        println!("Match: {}", xg_x.limbs == pk_x.limbs);
        
        // The issue might be that prove_dleq_mimc is called with rng after some consumption
        // Let's trace what prove_dleq_mimc would compute with fresh state
        let mut rng2 = ChaCha20Rng::seed_from_u64(42);
        let private_key2 = random_scalar(&mut rng2);  // consumes rng
        let _ = random_scalar(&mut rng2);  // mask consumes rng
        
        // Now rng2 is at same state as when evaluate_oprf_mimc calls prove_dleq_mimc
        // (assuming evaluate_oprf_mimc doesn't consume rng before prove)
        // Actually evaluate_oprf_mimc passes rng directly to prove_dleq_mimc
        
        // In prove_dleq_mimc, v = random_scalar(rng) is called
        let v_prove = random_scalar(&mut rng2);  // This is what prove would use
        
        println!("\nv value in prove: {:?}", v_prove.limbs);
        
        // Now check if verify reconstructs the same v
        // v_g = G * v and v_h = H * v in prove
        // v_g_reconstruct = r*G + c*x_g_cleared and v_h_reconstruct = r*H + c*x_h_cleared in verify
        // These should be equal if c and r are correct
        
        assert!(ev_x.limbs == xh_x.limbs, "evaluated should match x_h");
    }

    #[test]
    fn test_hash_input_comparison() {
        use rand::SeedableRng;
        use rand_chacha::ChaCha20Rng;
        use crate::babyjub::point::{base_point, ExtendedPointBigInt};
        use crate::babyjub::point::gen::native as point_native;
        use crate::babyjub::field256::gen::{modulus, scalar_order, BigInt256};
        use crate::toprf_server::{Share};
        use crate::toprf_server::eval::{hash_to_point_mimc, mask_point};
        use crate::toprf_server::dkg::random_scalar;
        
        let mut rng = ChaCha20Rng::seed_from_u64(42);
        let p = modulus();
        let order = scalar_order();
        
        // Create share
        let private_key = random_scalar(&mut rng);
        let share = Share {
            index: 1,
            private_key: private_key.clone(),
            public_key: point_native::scalar_mul(&base_point(), &private_key),
        };
        
        // Create masked request
        let secret_data = [
            BigInt256::from_u32(123),
            BigInt256::from_u32(456),
        ];
        let domain_sep = BigInt256::from_u32(1);
        let data_point = hash_to_point_mimc(&secret_data, &domain_sep);
        let mask = random_scalar(&mut rng);
        let masked_request = mask_point(&data_point, &mask);
        
        let h = &masked_request;
        let x = &share.private_key;
        let base = base_point();
        
        // === What prove computes ===
        let x_g_prove = point_native::scalar_mul(&base, x);
        let x_h_prove = point_native::scalar_mul(h, x);
        let x_g_cleared_prove = point_native::clear_cofactor(&x_g_prove);
        let x_h_cleared_prove = point_native::clear_cofactor(&x_h_prove);
        
        let v = random_scalar(&mut rng);  // This is what prove uses
        let v_g_prove = point_native::scalar_mul(&base, &v);
        let v_h_prove = point_native::scalar_mul(h, &v);
        
        // Build hash input (prove)
        fn get_byte_stream(points: &[&ExtendedPointBigInt]) -> Vec<u8> {
            let p = modulus();
            let mut byte_stream: Vec<u8> = Vec::new();
            for point in points {
                let (x, y) = point.to_affine(&p);
                byte_stream.extend_from_slice(&x.to_bytes_be_trimmed());
                byte_stream.extend_from_slice(&y.to_bytes_be_trimmed());
            }
            byte_stream
        }
        
        let prove_bytes = get_byte_stream(&[&base, &x_g_cleared_prove, &v_g_prove, &v_h_prove, h, &x_h_cleared_prove]);
        println!("PROVE hash input bytes ({} bytes):", prove_bytes.len());
        println!("  {:?}", hex::encode(&prove_bytes[..32.min(prove_bytes.len())]));
        
        // Compute c from prove
        use crate::babyjub::mimc_compat::mimc_hash;
        fn hash_bytes(byte_stream: &[u8]) -> BigInt256 {
            let order = scalar_order();
            let mut elements: Vec<BigInt256> = Vec::new();
            let mut offset = 0;
            while offset < byte_stream.len() {
                let chunk_len = (byte_stream.len() - offset).min(32);
                let chunk = &byte_stream[offset..offset + chunk_len];
                let mut padded = [0u8; 32];
                padded[32 - chunk_len..].copy_from_slice(chunk);
                elements.push(BigInt256::from_bytes_be(&padded));
                offset += 32;
            }
            // Reduce mod scalar_order for use as EC scalar
            let hash = mimc_hash(&elements);
            reduce_mod_order(&hash, &order)
        }
        let c = hash_bytes(&prove_bytes);
        println!("c from prove: {:?}", c.limbs);
        
        // Compute r
        let cofactor_x = {
            let cofactor = BigInt256::from_u32(8);
            x.mul_mod(&cofactor, &order)
        };
        let c_times_8x = c.mul_mod(&cofactor_x, &order);
        let r = v.sub_mod(&c_times_8x, &order);
        println!("r from prove: {:?}", r.limbs);
        
        // === What verify computes ===
        // Inputs to verify: c, r, x_g (public_key), x_h (evaluated_point), h (masked_request)
        let x_g_verify = &share.public_key;  // Same as x_g_prove
        let x_h_verify = &x_h_prove;  // Same as evaluated_point
        
        let x_g_cleared_verify = point_native::clear_cofactor(x_g_verify);
        let x_h_cleared_verify = point_native::clear_cofactor(x_h_verify);
        
        // Check cleared points match
        let (pgc_x, _) = x_g_cleared_prove.to_affine(&p);
        let (vgc_x, _) = x_g_cleared_verify.to_affine(&p);
        println!("\nx_g_cleared match: {}", pgc_x.limbs == vgc_x.limbs);
        
        let (phc_x, _) = x_h_cleared_prove.to_affine(&p);
        let (vhc_x, _) = x_h_cleared_verify.to_affine(&p);
        println!("x_h_cleared match: {}", phc_x.limbs == vhc_x.limbs);
        
        // Reconstruct v_g = r*G + c*x_g_cleared
        let r_g = point_native::scalar_mul(&base, &r);
        let c_xg = point_native::scalar_mul(&x_g_cleared_verify, &c);
        let v_g_verify = point_native::add_points(&r_g, &c_xg);
        
        // Reconstruct v_h = r*H + c*x_h_cleared
        let r_h = point_native::scalar_mul(h, &r);
        let c_xh = point_native::scalar_mul(&x_h_cleared_verify, &c);
        let v_h_verify = point_native::add_points(&r_h, &c_xh);
        
        // Check v_g and v_h match
        let (pvg_x, _) = v_g_prove.to_affine(&p);
        let (vvg_x, _) = v_g_verify.to_affine(&p);
        println!("v_g match: {}", pvg_x.limbs == vvg_x.limbs);
        
        let (pvh_x, _) = v_h_prove.to_affine(&p);
        let (vvh_x, _) = v_h_verify.to_affine(&p);
        println!("v_h match: {}", pvh_x.limbs == vvh_x.limbs);
        
        // Hash from verify side
        let verify_bytes = get_byte_stream(&[&base, &x_g_cleared_verify, &v_g_verify, &v_h_verify, h, &x_h_cleared_verify]);
        println!("\nVERIFY hash input bytes ({} bytes):", verify_bytes.len());
        println!("  {:?}", hex::encode(&verify_bytes[..32.min(verify_bytes.len())]));
        
        let expected_c = hash_bytes(&verify_bytes);
        println!("expected_c from verify: {:?}", expected_c.limbs);
        println!("c == expected_c: {}", c.limbs == expected_c.limbs);
        
        assert!(c.limbs == expected_c.limbs, "Hash should match");
    }

    #[test]
    fn test_scalar_arithmetic_debug() {
        use rand::SeedableRng;
        use rand_chacha::ChaCha20Rng;
        use crate::babyjub::point::{base_point};
        use crate::babyjub::point::gen::native as point_native;
        use crate::babyjub::field256::gen::{modulus, scalar_order, BigInt256};
        use crate::toprf_server::dkg::random_scalar;
        
        let mut rng = ChaCha20Rng::seed_from_u64(42);
        let p = modulus();
        let order = scalar_order();
        let base = base_point();
        
        let x = random_scalar(&mut rng);  // private key
        let _ = random_scalar(&mut rng);  // skip (mask)
        let v = random_scalar(&mut rng);  // v value
        
        // Compute c (simplified, just use a random value for testing)
        let c = random_scalar(&mut rng);
        
        // Compute r = v - c*8*x
        let cofactor = BigInt256::from_u32(8);
        let cofactor_x = x.mul_mod(&cofactor, &order);  // 8x
        let c_times_8x = c.mul_mod(&cofactor_x, &order);  // c * 8x
        let r = v.sub_mod(&c_times_8x, &order);  // v - c*8x
        
        println!("x = {:?}", x.limbs);
        println!("v = {:?}", v.limbs);
        println!("c = {:?}", c.limbs);
        println!("8x = {:?}", cofactor_x.limbs);
        println!("c*8x = {:?}", c_times_8x.limbs);
        println!("r = v - c*8x = {:?}", r.limbs);
        
        // Check: r + c*8x should equal v
        let reconstructed_v = r.add_mod(&c_times_8x, &order);
        println!("\nr + c*8x = {:?}", reconstructed_v.limbs);
        println!("v = {:?}", v.limbs);
        println!("Match: {}", reconstructed_v.limbs == v.limbs);
        
        // Now check point operations
        // v_g_prove = G * v
        let v_g_prove = point_native::scalar_mul(&base, &v);
        
        // v_g_verify should be r*G + c*(8*G*x)
        // But we compute it as r*G + c*x_g_cleared where x_g_cleared = 8*(G*x)
        
        // First compute x_g = G * x
        let x_g = point_native::scalar_mul(&base, &x);
        // Then x_g_cleared = 8 * x_g = 8 * G * x
        let x_g_cleared = point_native::clear_cofactor(&x_g);
        
        // r * G
        let r_g = point_native::scalar_mul(&base, &r);
        // c * x_g_cleared = c * (8 * G * x)
        let c_xg = point_native::scalar_mul(&x_g_cleared, &c);
        // v_g_verify = r*G + c*x_g_cleared
        let v_g_verify = point_native::add_points(&r_g, &c_xg);
        
        let (pvg_x, pvg_y) = v_g_prove.to_affine(&p);
        let (vvg_x, vvg_y) = v_g_verify.to_affine(&p);
        
        println!("\nv_g_prove.x = {:?}", pvg_x.limbs);
        println!("v_g_verify.x = {:?}", vvg_x.limbs);
        println!("Match: {}", pvg_x.limbs == vvg_x.limbs);
        
        // Alternative: compute (r + c*8x) * G directly
        let r_plus_c8x = r.add_mod(&c_times_8x, &order);
        let v_g_alt = point_native::scalar_mul(&base, &r_plus_c8x);
        let (altg_x, _) = v_g_alt.to_affine(&p);
        
        println!("\nAlternative: (r + c*8x) * G");
        println!("v_g_alt.x = {:?}", altg_x.limbs);
        println!("Match with prove: {}", altg_x.limbs == pvg_x.limbs);
        
        // So the issue is: r*G + c*(8*G*x) != (r + c*8x)*G
        // But these should be equal!
        // Let's verify c*x_g_cleared = (c*8x)*G
        
        let c8x_g = point_native::scalar_mul(&base, &c_times_8x);
        let (c8xg_x, _) = c8x_g.to_affine(&p);
        let (cxg_x, _) = c_xg.to_affine(&p);
        
        println!("\n(c*8x)*G.x = {:?}", c8xg_x.limbs);
        println!("c*(8*G*x).x = {:?}", cxg_x.limbs);
        println!("Match: {}", c8xg_x.limbs == cxg_x.limbs);
        
        assert!(pvg_x.limbs == vvg_x.limbs, "v_g should match");
    }

    #[test]
    fn test_compare_prove_output() {
        use rand::SeedableRng;
        use rand_chacha::ChaCha20Rng;
        use crate::babyjub::point::{base_point};
        use crate::babyjub::point::gen::native as point_native;
        use crate::babyjub::field256::gen::{modulus, scalar_order, BigInt256};
        use crate::toprf_server::eval::{hash_to_point_mimc, mask_point};
        use crate::toprf_server::dkg::random_scalar;
        
        let mut rng = ChaCha20Rng::seed_from_u64(42);
        let p = modulus();
        let order = scalar_order();
        let base = base_point();
        
        // Create values like in WASM flow
        let private_key = random_scalar(&mut rng);
        let secret_data = [
            BigInt256::from_u32(123),
            BigInt256::from_u32(456),
        ];
        let domain_sep = BigInt256::from_u32(1);
        let data_point = hash_to_point_mimc(&secret_data, &domain_sep);
        let mask = random_scalar(&mut rng);
        let masked_request = mask_point(&data_point, &mask);
        
        // Call prove_dleq_mimc directly
        let (c_actual, r_actual) = prove_dleq_mimc(&mut rng, &private_key, &masked_request).unwrap();
        
        println!("prove_dleq_mimc output:");
        println!("  c = {:?}", c_actual.limbs);
        println!("  r = {:?}", r_actual.limbs);
        
        // Now verify with the actual c and r
        let x_g = point_native::scalar_mul(&base, &private_key);
        let x_h = point_native::scalar_mul(&masked_request, &private_key);
        
        let valid = verify_dleq_mimc(&c_actual, &r_actual, &x_g, &x_h, &masked_request);
        println!("\nverify_dleq_mimc result: {}", valid);
        
        // Also print what verify computes for expected_c
        let x_g_cleared = point_native::clear_cofactor(&x_g);
        let x_h_cleared = point_native::clear_cofactor(&x_h);
        
        let r_g = point_native::scalar_mul(&base, &r_actual);
        let c_xg = point_native::scalar_mul(&x_g_cleared, &c_actual);
        let v_g_verify = point_native::add_points(&r_g, &c_xg);
        
        let r_h = point_native::scalar_mul(&masked_request, &r_actual);
        let c_xh = point_native::scalar_mul(&x_h_cleared, &c_actual);
        let v_h_verify = point_native::add_points(&r_h, &c_xh);
        
        let expected_c = hash_points_to_scalar_mimc(&[&base, &x_g_cleared, &v_g_verify, &v_h_verify, &masked_request, &x_h_cleared]);
        
        println!("\nIn verify:");
        println!("  expected_c = {:?}", expected_c.limbs);
        println!("  c_actual = {:?}", c_actual.limbs);
        println!("  match: {}", expected_c.limbs == c_actual.limbs);
        
        assert!(valid, "Verification should pass");
    }

    #[test]
    fn test_dleq_with_simple_vs_hash_point() {
        use rand::SeedableRng;
        use rand_chacha::ChaCha20Rng;
        use crate::babyjub::point::base_point;
        use crate::babyjub::point::gen::native as point_native;
        use crate::babyjub::field256::gen::{BigInt256};
        use crate::toprf_server::eval::{hash_to_point_mimc, mask_point};
        use crate::toprf_server::dkg::random_scalar;
        
        println!("Test 1: masked_request = G * random_scalar");
        {
            let mut rng = ChaCha20Rng::seed_from_u64(42);
            let private_key = random_scalar(&mut rng);
            let request_scalar = random_scalar(&mut rng);
            let masked_request = point_native::scalar_mul(&base_point(), &request_scalar);
            
            let (c, r) = prove_dleq_mimc(&mut rng, &private_key, &masked_request).unwrap();
            let x_g = point_native::scalar_mul(&base_point(), &private_key);
            let x_h = point_native::scalar_mul(&masked_request, &private_key);
            
            let valid = verify_dleq_mimc(&c, &r, &x_g, &x_h, &masked_request);
            println!("  Result: {}", valid);
        }
        
        println!("\nTest 2: masked_request = hash_to_point_mimc(...) * mask");
        {
            let mut rng = ChaCha20Rng::seed_from_u64(42);
            let private_key = random_scalar(&mut rng);
            let secret_data = [
                BigInt256::from_u32(123),
                BigInt256::from_u32(456),
            ];
            let domain_sep = BigInt256::from_u32(1);
            let data_point = hash_to_point_mimc(&secret_data, &domain_sep);
            let mask = random_scalar(&mut rng);
            let masked_request = mask_point(&data_point, &mask);
            
            let (c, r) = prove_dleq_mimc(&mut rng, &private_key, &masked_request).unwrap();
            let x_g = point_native::scalar_mul(&base_point(), &private_key);
            let x_h = point_native::scalar_mul(&masked_request, &private_key);
            
            let valid = verify_dleq_mimc(&c, &r, &x_g, &x_h, &masked_request);
            println!("  Result: {}", valid);
        }
        
        println!("\nTest 3: masked_request = data_point directly (no mask)");
        {
            let mut rng = ChaCha20Rng::seed_from_u64(42);
            let private_key = random_scalar(&mut rng);
            let secret_data = [
                BigInt256::from_u32(123),
                BigInt256::from_u32(456),
            ];
            let domain_sep = BigInt256::from_u32(1);
            let data_point = hash_to_point_mimc(&secret_data, &domain_sep);
            // Use data_point directly without masking
            
            let (c, r) = prove_dleq_mimc(&mut rng, &private_key, &data_point).unwrap();
            let x_g = point_native::scalar_mul(&base_point(), &private_key);
            let x_h = point_native::scalar_mul(&data_point, &private_key);
            
            let valid = verify_dleq_mimc(&c, &r, &x_g, &x_h, &data_point);
            println!("  Result: {}", valid);
        }
        
        println!("\nTest 4: masked_request = G * mask (simpler)");
        {
            let mut rng = ChaCha20Rng::seed_from_u64(42);
            let private_key = random_scalar(&mut rng);
            let _ = random_scalar(&mut rng);  // skip
            let mask = random_scalar(&mut rng);
            let masked_request = point_native::scalar_mul(&base_point(), &mask);
            
            let (c, r) = prove_dleq_mimc(&mut rng, &private_key, &masked_request).unwrap();
            let x_g = point_native::scalar_mul(&base_point(), &private_key);
            let x_h = point_native::scalar_mul(&masked_request, &private_key);
            
            let valid = verify_dleq_mimc(&c, &r, &x_g, &x_h, &masked_request);
            println!("  Result: {}", valid);
        }
    }

    #[test]
    fn test_scalar_mul_commutativity() {
        use rand::SeedableRng;
        use rand_chacha::ChaCha20Rng;
        use crate::babyjub::point::base_point;
        use crate::babyjub::point::gen::native as point_native;
        use crate::babyjub::field256::gen::{modulus, scalar_order, BigInt256};
        use crate::toprf_server::eval::hash_to_point_mimc;
        use crate::toprf_server::dkg::random_scalar;
        
        let mut rng = ChaCha20Rng::seed_from_u64(42);
        let p = modulus();
        let order = scalar_order();
        
        let a = random_scalar(&mut rng);
        let b = random_scalar(&mut rng);
        
        // Method 1: G * (a*b)
        let ab = a.mul_mod(&b, &order);
        let method1 = point_native::scalar_mul(&base_point(), &ab);
        
        // Method 2: (G * a) * b
        let ga = point_native::scalar_mul(&base_point(), &a);
        let method2 = point_native::scalar_mul(&ga, &b);
        
        // Method 3: (G * b) * a
        let gb = point_native::scalar_mul(&base_point(), &b);
        let method3 = point_native::scalar_mul(&gb, &a);
        
        let (m1_x, m1_y) = method1.to_affine(&p);
        let (m2_x, m2_y) = method2.to_affine(&p);
        let (m3_x, m3_y) = method3.to_affine(&p);
        
        println!("Method 1 (G * ab): ({:?})", m1_x.limbs);
        println!("Method 2 ((G*a)*b): ({:?})", m2_x.limbs);
        println!("Method 3 ((G*b)*a): ({:?})", m3_x.limbs);
        println!("1==2: {}, 1==3: {}, 2==3: {}", 
            m1_x.limbs == m2_x.limbs,
            m1_x.limbs == m3_x.limbs,
            m2_x.limbs == m3_x.limbs);
        
        // Now test with hash_to_point
        let secret_data = [
            BigInt256::from_u32(123),
            BigInt256::from_u32(456),
        ];
        let domain_sep = BigInt256::from_u32(1);
        let h = hash_to_point_mimc(&secret_data, &domain_sep);
        
        let mask = random_scalar(&mut rng);
        let priv_key = random_scalar(&mut rng);
        
        // Method A: h * mask * priv_key (sequential)
        let h_mask = point_native::scalar_mul(&h, &mask);
        let methodA = point_native::scalar_mul(&h_mask, &priv_key);
        
        // Method B: h * (mask * priv_key)
        let mask_priv = mask.mul_mod(&priv_key, &order);
        let methodB = point_native::scalar_mul(&h, &mask_priv);
        
        // Method C: (h * priv_key) * mask
        let h_priv = point_native::scalar_mul(&h, &priv_key);
        let methodC = point_native::scalar_mul(&h_priv, &mask);
        
        let (ma_x, _) = methodA.to_affine(&p);
        let (mb_x, _) = methodB.to_affine(&p);
        let (mc_x, _) = methodC.to_affine(&p);
        
        println!("\nWith hash_to_point:");
        println!("Method A (h*mask)*priv: ({:?})", ma_x.limbs);
        println!("Method B h*(mask*priv): ({:?})", mb_x.limbs);
        println!("Method C (h*priv)*mask: ({:?})", mc_x.limbs);
        println!("A==B: {}, A==C: {}, B==C: {}", 
            ma_x.limbs == mb_x.limbs,
            ma_x.limbs == mc_x.limbs,
            mb_x.limbs == mc_x.limbs);
        
        assert!(m1_x.limbs == m2_x.limbs, "Scalar mul should commute with base");
        assert!(ma_x.limbs == mb_x.limbs, "Scalar mul should commute with hash point");
    }

    #[test]
    fn test_clear_cofactor_behavior() {
        use rand::SeedableRng;
        use rand_chacha::ChaCha20Rng;
        use crate::babyjub::point::base_point;
        use crate::babyjub::point::gen::native as point_native;
        use crate::babyjub::field256::gen::{modulus, BigInt256};
        use crate::toprf_server::eval::{hash_to_point_mimc, mask_point};
        use crate::toprf_server::dkg::random_scalar;
        
        let mut rng = ChaCha20Rng::seed_from_u64(42);
        let p = modulus();
        
        let private_key = random_scalar(&mut rng);
        let base = base_point();
        
        // Test 1: G * scalar
        let scalar1 = random_scalar(&mut rng);
        let point1 = point_native::scalar_mul(&base, &scalar1);
        let point1_priv = point_native::scalar_mul(&point1, &private_key);
        let point1_priv_cleared = point_native::clear_cofactor(&point1_priv);
        
        println!("Test 1: G * scalar");
        let (p1_x, _) = point1_priv.to_affine(&p);
        let (p1c_x, _) = point1_priv_cleared.to_affine(&p);
        println!("  before clear: {:?}", p1_x.limbs);
        println!("  after clear: {:?}", p1c_x.limbs);
        
        // Test 2: hash_to_point * mask
        let secret_data = [
            BigInt256::from_u32(123),
            BigInt256::from_u32(456),
        ];
        let domain_sep = BigInt256::from_u32(1);
        let data_point = hash_to_point_mimc(&secret_data, &domain_sep);
        let mask = random_scalar(&mut rng);
        let masked = mask_point(&data_point, &mask);
        let masked_priv = point_native::scalar_mul(&masked, &private_key);
        let masked_priv_cleared = point_native::clear_cofactor(&masked_priv);
        
        println!("\nTest 2: hash_to_point * mask");
        let (p2_x, _) = masked_priv.to_affine(&p);
        let (p2c_x, _) = masked_priv_cleared.to_affine(&p);
        println!("  before clear: {:?}", p2_x.limbs);
        println!("  after clear: {:?}", p2c_x.limbs);
        
        // Check if 8*P == 8 times P (i.e., clear_cofactor produces consistent results)
        let eight = BigInt256::from_u32(8);
        let p2_times_8 = point_native::scalar_mul(&masked_priv, &eight);
        let (p2x8_x, _) = p2_times_8.to_affine(&p);
        println!("  8 * (masked * priv) via scalar_mul: {:?}", p2x8_x.limbs);
        println!("  via clear_cofactor: {:?}", p2c_x.limbs);
        println!("  match: {}", p2x8_x.limbs == p2c_x.limbs);
        
        // Also check the hash_to_point directly
        let data_priv = point_native::scalar_mul(&data_point, &private_key);
        let data_priv_cleared = point_native::clear_cofactor(&data_priv);
        
        println!("\nTest 3: hash_to_point directly (no mask)");
        let (p3_x, _) = data_priv.to_affine(&p);
        let (p3c_x, _) = data_priv_cleared.to_affine(&p);
        println!("  before clear: {:?}", p3_x.limbs);
        println!("  after clear: {:?}", p3c_x.limbs);
    }

    #[test]
    fn test_detailed_dleq_trace() {
        use rand::SeedableRng;
        use rand_chacha::ChaCha20Rng;
        use crate::babyjub::point::base_point;
        use crate::babyjub::point::gen::native as point_native;
        use crate::babyjub::field256::gen::{modulus, scalar_order, BigInt256};
        use crate::toprf_server::eval::{hash_to_point_mimc, mask_point};
        use crate::toprf_server::dkg::random_scalar;
        use crate::babyjub::mimc_compat::mimc_hash;
        
        let p = modulus();
        let order = scalar_order();
        let base = base_point();
        
        println!("=== FAILING CASE: hash_to_point * mask ===");
        {
            let mut rng = ChaCha20Rng::seed_from_u64(42);
            let private_key = random_scalar(&mut rng);
            let secret_data = [
                BigInt256::from_u32(123),
                BigInt256::from_u32(456),
            ];
            let domain_sep = BigInt256::from_u32(1);
            let data_point = hash_to_point_mimc(&secret_data, &domain_sep);
            let mask = random_scalar(&mut rng);
            let h = mask_point(&data_point, &mask);
            
            // ---- PROVE ----
            let x = &private_key;
            let x_g = point_native::scalar_mul(&base, x);
            let x_h = point_native::scalar_mul(&h, x);
            let x_g_cleared = point_native::clear_cofactor(&x_g);
            let x_h_cleared = point_native::clear_cofactor(&x_h);
            
            let v = random_scalar(&mut rng);
            let v_g = point_native::scalar_mul(&base, &v);
            let v_h = point_native::scalar_mul(&h, &v);
            
            println!("\nPROVE:");
            println!("  x (private_key) = {:?}", x.limbs);
            println!("  v (random) = {:?}", v.limbs);
            
            // Hash to get c
            fn get_byte_stream(points: &[&crate::babyjub::point::ExtendedPointBigInt]) -> Vec<u8> {
                let p = modulus();
                let mut bytes: Vec<u8> = Vec::new();
                for pt in points {
                    let (px, py) = pt.to_affine(&p);
                    bytes.extend_from_slice(&px.to_bytes_be_trimmed());
                    bytes.extend_from_slice(&py.to_bytes_be_trimmed());
                }
                bytes
            }
            
            fn hash_bytes(bytes: &[u8]) -> BigInt256 {
                let mut elements: Vec<BigInt256> = Vec::new();
                let mut offset = 0;
                while offset < bytes.len() {
                    let chunk_len = (bytes.len() - offset).min(32);
                    let chunk = &bytes[offset..offset + chunk_len];
                    let mut padded = [0u8; 32];
                    padded[32 - chunk_len..].copy_from_slice(chunk);
                    elements.push(BigInt256::from_bytes_be(&padded));
                    offset += 32;
                }
                mimc_hash(&elements)
            }
            
            let prove_bytes = get_byte_stream(&[&base, &x_g_cleared, &v_g, &v_h, &h, &x_h_cleared]);
            let c = hash_bytes(&prove_bytes);
            
            let cofactor = BigInt256::from_u32(8);
            let cofactor_x = x.mul_mod(&cofactor, &order);
            let c_times_8x = c.mul_mod(&cofactor_x, &order);
            let r = v.sub_mod(&c_times_8x, &order);
            
            println!("  c = {:?}", c.limbs);
            println!("  r = {:?}", r.limbs);
            println!("  8x = {:?}", cofactor_x.limbs);
            println!("  c*8x = {:?}", c_times_8x.limbs);
            
            // Check: r + c*8x should = v
            let check_v = r.add_mod(&c_times_8x, &order);
            println!("  r + c*8x = {:?}", check_v.limbs);
            println!("  v = {:?}", v.limbs);
            println!("  match: {}", check_v.limbs == v.limbs);
            
            // ---- VERIFY ----
            println!("\nVERIFY:");
            let x_g_cleared_v = point_native::clear_cofactor(&x_g);
            let x_h_cleared_v = point_native::clear_cofactor(&x_h);
            
            let r_g = point_native::scalar_mul(&base, &r);
            let c_xg = point_native::scalar_mul(&x_g_cleared_v, &c);
            let v_g_v = point_native::add_points(&r_g, &c_xg);
            
            let r_h = point_native::scalar_mul(&h, &r);
            let c_xh = point_native::scalar_mul(&x_h_cleared_v, &c);
            let v_h_v = point_native::add_points(&r_h, &c_xh);
            
            let (vg_x, vg_y) = v_g.to_affine(&p);
            let (vgv_x, vgv_y) = v_g_v.to_affine(&p);
            println!("  v_g from prove: ({:?})", vg_x.limbs);
            println!("  v_g from verify: ({:?})", vgv_x.limbs);
            println!("  v_g match: {}", vg_x.limbs == vgv_x.limbs);
            
            let (vh_x, vh_y) = v_h.to_affine(&p);
            let (vhv_x, vhv_y) = v_h_v.to_affine(&p);
            println!("  v_h from prove: ({:?})", vh_x.limbs);
            println!("  v_h from verify: ({:?})", vhv_x.limbs);
            println!("  v_h match: {}", vh_x.limbs == vhv_x.limbs);
            
            // Manually compute v*G to compare
            let v_g_manual = point_native::scalar_mul(&base, &v);
            let (vgm_x, _) = v_g_manual.to_affine(&p);
            println!("  v*G manual: ({:?})", vgm_x.limbs);
            
            // Check (r + c*8x)*G
            let r_plus_c8x = r.add_mod(&c_times_8x, &order);
            let check_vg = point_native::scalar_mul(&base, &r_plus_c8x);
            let (cvg_x, _) = check_vg.to_affine(&p);
            println!("  (r+c*8x)*G: ({:?})", cvg_x.limbs);
        }
    }
    #[test]
    fn test_minimal_dleq() {
        use rand::SeedableRng;
        use rand_chacha::ChaCha20Rng;
        use crate::babyjub::point::base_point;
        use crate::babyjub::point::gen::native as point_native;
        use crate::babyjub::field256::gen::{modulus, BigInt256};
        use crate::toprf_server::dkg::random_scalar;
        
        let p = modulus();
        
        // Test 1: Same as test_prove_verify_dleq_mimc (PASSES)
        println!("Test 1: h = G * h_scalar");
        {
            let mut rng = ChaCha20Rng::seed_from_u64(12345);
            let x = random_scalar(&mut rng);
            let h_scalar = random_scalar(&mut rng);
            let h = point_native::scalar_mul(&base_point(), &h_scalar);
            
            let (c, r) = prove_dleq_mimc(&mut rng, &x, &h).unwrap();
            let x_g = point_native::scalar_mul(&base_point(), &x);
            let x_h = point_native::scalar_mul(&h, &x);
            
            let valid = verify_dleq_mimc(&c, &r, &x_g, &x_h, &h);
            println!("  Result: {}", valid);
            assert!(valid, "Test 1 should pass");
        }
        
        // Test 2: Different seed
        println!("\nTest 2: h = G * h_scalar (seed 42)");
        {
            let mut rng = ChaCha20Rng::seed_from_u64(42);
            let x = random_scalar(&mut rng);
            let h_scalar = random_scalar(&mut rng);
            let h = point_native::scalar_mul(&base_point(), &h_scalar);
            
            let (c, r) = prove_dleq_mimc(&mut rng, &x, &h).unwrap();
            let x_g = point_native::scalar_mul(&base_point(), &x);
            let x_h = point_native::scalar_mul(&h, &x);
            
            let valid = verify_dleq_mimc(&c, &r, &x_g, &x_h, &h);
            println!("  Result: {}", valid);
            assert!(valid, "Test 2 should pass");
        }
        
        // Test 3: h = G * (a * b) where we first compute G*a then multiply by b
        println!("\nTest 3: h = (G * a) * b");
        {
            let mut rng = ChaCha20Rng::seed_from_u64(42);
            let x = random_scalar(&mut rng);
            let a = random_scalar(&mut rng);
            let b = random_scalar(&mut rng);
            let g_a = point_native::scalar_mul(&base_point(), &a);
            let h = point_native::scalar_mul(&g_a, &b);  // This is the key difference!
            
            let (c, r) = prove_dleq_mimc(&mut rng, &x, &h).unwrap();
            let x_g = point_native::scalar_mul(&base_point(), &x);
            let x_h = point_native::scalar_mul(&h, &x);
            
            let valid = verify_dleq_mimc(&c, &r, &x_g, &x_h, &h);
            println!("  Result: {}", valid);
        }
    }

    #[test]
    fn test_seed_comparison() {
        use rand::SeedableRng;
        use rand_chacha::ChaCha20Rng;
        use crate::babyjub::point::base_point;
        use crate::babyjub::point::gen::native as point_native;
        use crate::babyjub::field256::gen::{modulus, scalar_order, BigInt256};
        use crate::toprf_server::dkg::random_scalar;
        
        let p = modulus();
        let order = scalar_order();
        
        for seed in [12345u64, 42u64] {
            println!("\n=== SEED {} ===", seed);
            let mut rng = ChaCha20Rng::seed_from_u64(seed);
            let x = random_scalar(&mut rng);
            let h_scalar = random_scalar(&mut rng);
            let h = point_native::scalar_mul(&base_point(), &h_scalar);
            let v = random_scalar(&mut rng);  // This is what prove_dleq_mimc uses internally
            
            println!("x = {:?}", x.limbs);
            println!("h_scalar = {:?}", h_scalar.limbs);
            println!("v = {:?}", v.limbs);
            
            // Compute what prove does
            let base = base_point();
            let x_g = point_native::scalar_mul(&base, &x);
            let x_h = point_native::scalar_mul(&h, &x);
            let v_g = point_native::scalar_mul(&base, &v);
            let v_h = point_native::scalar_mul(&h, &v);
            
            // Hash
            let c = hash_points_to_scalar_mimc(&[&base, &x_g, &v_g, &v_h, &h, &x_h]);
            println!("c = {:?}", c.limbs);
            
            // r = v - c*x
            let c_times_x = c.mul_mod(&x, &order);
            let r = v.sub_mod(&c_times_x, &order);
            println!("r = {:?}", r.limbs);
            
            // Check: r + c*x should equal v
            let check_v = r.add_mod(&c_times_x, &order);
            println!("r + c*x = {:?}", check_v.limbs);
            println!("v = {:?}", v.limbs);
            println!("scalar check: {}", check_v.limbs == v.limbs);
            
            // Now verify reconstruction
            let r_g = point_native::scalar_mul(&base, &r);
            let c_xg = point_native::scalar_mul(&x_g, &c);
            let v_g_recon = point_native::add_points(&r_g, &c_xg);
            
            let (vg_x, _) = v_g.to_affine(&p);
            let (vgr_x, _) = v_g_recon.to_affine(&p);
            println!("v_g original: {:?}", vg_x.limbs);
            println!("v_g reconstructed: {:?}", vgr_x.limbs);
            println!("v_g match: {}", vg_x.limbs == vgr_x.limbs);
        }
    }

    #[test]
    fn test_gnark_c_reduction() {
        // Test with a c value that's larger than scalar_order (simulating gnark's unreduced c)
        use crate::babyjub::field256::gen::{modulus, scalar_order, BigInt256};
        use crate::babyjub::point::{base_point, ExtendedPointBigInt};
        use crate::babyjub::point::gen::native as point_native;
        use crate::toprf_server::dkg::random_scalar;
        use rand::SeedableRng;
        use rand_chacha::ChaCha20Rng;
        
        let mut rng = ChaCha20Rng::seed_from_u64(12345);
        let p = modulus();
        let order = scalar_order();
        let base = base_point();
        
        // Generate test values
        let x = random_scalar(&mut rng);
        let h_scalar = random_scalar(&mut rng);
        let h = point_native::scalar_mul(&base, &h_scalar);
        let v = random_scalar(&mut rng);
        
        // Compute what gnark would compute
        let x_g = point_native::scalar_mul(&base, &x);
        let x_h = point_native::scalar_mul(&h, &x);
        let v_g = point_native::scalar_mul(&base, &v);
        let v_h = point_native::scalar_mul(&h, &v);
        
        // Simulate gnark's hash (NOT reduced) - just use MiMC hash without reduction
        use crate::babyjub::mimc_compat::mimc_hash;
        fn hash_points_unreduced(points: &[&ExtendedPointBigInt]) -> BigInt256 {
            let p = modulus();
            let mut byte_stream: Vec<u8> = Vec::new();
            for point in points {
                let (x, y) = point.to_affine(&p);
                byte_stream.extend_from_slice(&x.to_bytes_be_trimmed());
                byte_stream.extend_from_slice(&y.to_bytes_be_trimmed());
            }
            let mut elements: Vec<BigInt256> = Vec::new();
            let mut offset = 0;
            while offset < byte_stream.len() {
                let chunk_len = (byte_stream.len() - offset).min(32);
                let chunk = &byte_stream[offset..offset + chunk_len];
                let mut padded = [0u8; 32];
                padded[32 - chunk_len..].copy_from_slice(chunk);
                elements.push(BigInt256::from_bytes_be(&padded));
                offset += 32;
            }
            mimc_hash(&elements)  // NOT reduced
        }
        
        let c_gnark = hash_points_unreduced(&[&base, &x_g, &v_g, &v_h, &h, &x_h]);
        
        // gnark's r = v - c * x mod order (using unreduced c)
        let c_times_x = c_gnark.mul_mod(&x, &order);
        let r_gnark = v.sub_mod(&c_times_x, &order);
        
        println!("c_gnark (unreduced): {:?}", c_gnark.limbs);
        println!("c_gnark > order: {}", c_gnark.cmp(&order) > 0);
        
        // Now simulate stwo's verify
        let c_reduced = reduce_mod_order(&c_gnark, &order);
        println!("c_reduced: {:?}", c_reduced.limbs);
        
        // Reconstruct v_g using c_reduced
        let r_g = point_native::scalar_mul(&base, &r_gnark);
        let c_xg = point_native::scalar_mul(&x_g, &c_reduced);
        let v_g_recon = point_native::add_points(&r_g, &c_xg);
        
        // Check if v_g_recon == v_g
        let (vg_x, _) = v_g.to_affine(&p);
        let (vgr_x, _) = v_g_recon.to_affine(&p);
        println!("v_g original: {:?}", vg_x.limbs);
        println!("v_g reconstructed: {:?}", vgr_x.limbs);
        println!("v_g match: {}", vg_x.limbs == vgr_x.limbs);
        
        // Compute expected_c using stwo's method (with reduction)
        let expected_c = hash_points_to_scalar_mimc(&[&base, &x_g, &v_g_recon, &point_native::add_points(&point_native::scalar_mul(&h, &r_gnark), &point_native::scalar_mul(&x_h, &c_reduced)), &h, &x_h]);
        println!("expected_c: {:?}", expected_c.limbs);
        println!("c_reduced == expected_c: {}", c_reduced.limbs == expected_c.limbs);
    }

    #[test]
    fn test_gnark_c_large_value() {
        // Test with seed 999 which might produce c > order
        use crate::babyjub::field256::gen::{modulus, scalar_order, BigInt256};
        use crate::babyjub::point::{base_point, ExtendedPointBigInt};
        use crate::babyjub::point::gen::native as point_native;
        use crate::toprf_server::dkg::random_scalar;
        use rand::SeedableRng;
        use rand_chacha::ChaCha20Rng;
        use crate::babyjub::mimc_compat::mimc_hash;
        
        let p = modulus();
        let order = scalar_order();
        let base = base_point();
        
        // Try multiple seeds to find one where c > order
        for seed in [42u64, 99, 123, 456, 789, 1000, 2000, 3000, 4000, 5000] {
            let mut rng = ChaCha20Rng::seed_from_u64(seed);
            
            let x = random_scalar(&mut rng);
            let h_scalar = random_scalar(&mut rng);
            let h = point_native::scalar_mul(&base, &h_scalar);
            let v = random_scalar(&mut rng);
            
            let x_g = point_native::scalar_mul(&base, &x);
            let x_h = point_native::scalar_mul(&h, &x);
            let v_g = point_native::scalar_mul(&base, &v);
            let v_h = point_native::scalar_mul(&h, &v);
            
            fn hash_points_unreduced(points: &[&ExtendedPointBigInt]) -> BigInt256 {
                let p = modulus();
                let mut byte_stream: Vec<u8> = Vec::new();
                for point in points {
                    let (x, y) = point.to_affine(&p);
                    byte_stream.extend_from_slice(&x.to_bytes_be_trimmed());
                    byte_stream.extend_from_slice(&y.to_bytes_be_trimmed());
                }
                let mut elements: Vec<BigInt256> = Vec::new();
                let mut offset = 0;
                while offset < byte_stream.len() {
                    let chunk_len = (byte_stream.len() - offset).min(32);
                    let chunk = &byte_stream[offset..offset + chunk_len];
                    let mut padded = [0u8; 32];
                    padded[32 - chunk_len..].copy_from_slice(chunk);
                    elements.push(BigInt256::from_bytes_be(&padded));
                    offset += 32;
                }
                mimc_hash(&elements)
            }
            
            let c = hash_points_unreduced(&[&base, &x_g, &v_g, &v_h, &h, &x_h]);
            let is_large = c.cmp(&order) >= 0;
            
            if is_large {
                println!("\nFound large c with seed {}", seed);
                println!("c (unreduced): {:?}", c.limbs);
                println!("order:         {:?}", order.limbs);
                
                // Do the full verification test
                let c_times_x = c.mul_mod(&x, &order);
                let r = v.sub_mod(&c_times_x, &order);
                
                let c_reduced = reduce_mod_order(&c, &order);
                println!("c_reduced:     {:?}", c_reduced.limbs);
                
                // Reconstruct
                let r_g = point_native::scalar_mul(&base, &r);
                let c_xg = point_native::scalar_mul(&x_g, &c_reduced);
                let v_g_recon = point_native::add_points(&r_g, &c_xg);
                
                let (vg_x, _) = v_g.to_affine(&p);
                let (vgr_x, _) = v_g_recon.to_affine(&p);
                println!("v_g match: {}", vg_x.limbs == vgr_x.limbs);
                
                // Expected c
                let v_h_recon = point_native::add_points(
                    &point_native::scalar_mul(&h, &r),
                    &point_native::scalar_mul(&x_h, &c_reduced)
                );
                let expected_c = hash_points_to_scalar_mimc(&[&base, &x_g, &v_g_recon, &v_h_recon, &h, &x_h]);
                println!("expected_c:    {:?}", expected_c.limbs);
                println!("c_reduced == expected_c: {}", c_reduced.limbs == expected_c.limbs);
                
                return;
            }
        }
        println!("No seed found with c > order");
    }

    #[test]
    fn test_base_point_hash_debug() {
        // Debug test to print exact hash inputs for base point
        // This helps compare with gnark's HashPointsToScalar
        use crate::babyjub::mimc_compat::mimc_hash;

        let p = modulus();
        let base = base_point();

        // Get affine coordinates
        let (x, y) = base.to_affine(&p);

        // Get trimmed bytes (like Go's big.Int.Bytes())
        let x_bytes = x.to_bytes_be_trimmed();
        let y_bytes = y.to_bytes_be_trimmed();

        // Get full 32-byte representation
        let x_full = x.to_bytes_be();
        let y_full = y.to_bytes_be();

        println!("=== Base Point Hash Debug ===");
        println!("x coordinate (trimmed, {} bytes): {}", x_bytes.len(), hex::encode(&x_bytes));
        println!("y coordinate (trimmed, {} bytes): {}", y_bytes.len(), hex::encode(&y_bytes));
        println!("x coordinate (full 32 bytes): {}", hex::encode(&x_full));
        println!("y coordinate (full 32 bytes): {}", hex::encode(&y_full));

        // Convert back to BigInt256 (this is what mimc_hash receives)
        let x_elem = BigInt256::from_bytes_be(&x_bytes);
        let y_elem = BigInt256::from_bytes_be(&y_bytes);

        println!("x element limbs: {:?}", x_elem.limbs);
        println!("y element limbs: {:?}", y_elem.limbs);

        // Hash just this point
        let hash = mimc_hash(&[x_elem, y_elem]);
        let hash_bytes = hash.to_bytes_be();
        println!("MiMC hash of base point: {}", hex::encode(&hash_bytes));

        // Now test the full hash_points_to_scalar_mimc
        let c = hash_points_to_scalar_mimc(&[&base]);
        let c_bytes = c.to_bytes_be();
        println!("hash_points_to_scalar_mimc([base]): {}", hex::encode(&c_bytes));

        // Compare with gnark's known base point coordinates
        // gnark base point X: 0x2ef3f9b423a2c8c74e9803958f6c320e854a1c1c06cd5cc8fd221dc052d76df7
        // gnark base point Y: 0x05a01167ea785d3f784224644a68e4067532c815f5f6d57d984b5c0e9c6c6b46
        println!("\n=== Expected gnark base point ===");
        println!("gnark X: 2ef3f9b423a2c8c74e9803958f6c320e854a1c1c06cd5cc8fd221dc052d76df7");
        println!("gnark Y: 05a01167ea785d3f784224644a68e4067532c815f5f6d57d984b5c0e9c6c6b46");
    }
