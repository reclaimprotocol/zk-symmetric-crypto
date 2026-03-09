//! DLEQ (Discrete Log Equality) proofs for TOPRF.
//!
//! Proves that log_G(xG) = log_H(xH) without revealing x.
//! This is used to prove the server used the correct private key.
//!
//! Based on RFC 9497 (OPRF) with cofactor clearing for small subgroup protection.

use rand::Rng;

use super::dkg::random_scalar;
use crate::babyjub::field256::gen::{modulus, scalar_order, BigInt256};
use crate::babyjub::mimc::gen::hash_field256_native;
use crate::babyjub::point::gen::native as point_native;
use crate::babyjub::point::{base_point, ExtendedPointBigInt};

/// Baby Jubjub cofactor (8).
const COFACTOR: u32 = 8;

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

/// Generate a DLEQ proof that log_G(xG) = log_H(xH).
///
/// # Arguments
/// * `x` - The secret scalar (private key)
/// * `h` - The base point H (masked client point)
///
/// # Returns
/// * `(c, r)` - The DLEQ proof components
/// * Returns None if any point is in the small subgroup
pub fn prove_dleq<R: Rng>(
    rng: &mut R,
    x: &BigInt256,
    h: &ExtendedPointBigInt,
) -> Option<(BigInt256, BigInt256)> {
    let modulus = modulus();
    let base = base_point();

    // Compute xG = G * x
    let x_g = point_native::scalar_mul(&base, x);

    // Compute xH = H * x
    let x_h = point_native::scalar_mul(h, x);

    // Clear cofactors (per RFC 9497)
    let x_g_cleared = clear_cofactor(&x_g)?;
    let x_h_cleared = clear_cofactor(&x_h)?;

    // Generate random v
    let v = random_scalar(rng);

    // Compute vG = G * v
    let v_g = point_native::scalar_mul(&base, &v);

    // Compute vH = H * v
    let v_h = point_native::scalar_mul(h, &v);

    // Convert points to affine for hashing
    let (base_x, base_y) = base.to_affine(&modulus);
    let (xg_x, xg_y) = x_g_cleared.to_affine(&modulus);
    let (vg_x, vg_y) = v_g.to_affine(&modulus);
    let (vh_x, vh_y) = v_h.to_affine(&modulus);
    let (h_x, h_y) = h.to_affine(&modulus);
    let (xh_x, xh_y) = x_h_cleared.to_affine(&modulus);

    // Compute challenge: c = Hash(G, xG_cleared, vG, vH, H, xH_cleared)
    let hash_inputs = vec![
        base_x, base_y, xg_x, xg_y, vg_x, vg_y, vh_x, vh_y, h_x, h_y, xh_x, xh_y,
    ];

    let c = hash_to_scalar(&hash_inputs);

    // Compute r = v - c * (8 * x) mod scalar_order
    // The factor of 8 is for cofactor clearing in the verification
    // Note: Scalar arithmetic uses the Baby Jubjub subgroup order, not the base field modulus
    let order = scalar_order();
    let cofactor_x = {
        let cofactor = BigInt256::from_limbs([COFACTOR, 0, 0, 0, 0, 0, 0, 0, 0]);
        x.mul_mod(&cofactor, &order)
    };
    let c_times_8x = c.mul_mod(&cofactor_x, &order);
    let r = v.sub_mod(&c_times_8x, &order);

    Some((c, r))
}

/// Verify a DLEQ proof.
///
/// # Arguments
/// * `c` - The challenge from the proof
/// * `r` - The response from the proof
/// * `x_g` - Point xG (server public key or G * share_key)
/// * `x_h` - Point xH (evaluated point = H * share_key)
/// * `h` - Point H (masked client request)
///
/// # Returns
/// * `true` if the proof is valid
pub fn verify_dleq(
    c: &BigInt256,
    r: &BigInt256,
    x_g: &ExtendedPointBigInt,
    x_h: &ExtendedPointBigInt,
    h: &ExtendedPointBigInt,
) -> bool {
    let modulus = modulus();
    let base = base_point();

    // Clear cofactors
    let x_g_cleared = match clear_cofactor(x_g) {
        Some(p) => p,
        None => return false,
    };
    let x_h_cleared = match clear_cofactor(x_h) {
        Some(p) => p,
        None => return false,
    };

    // Reconstruct vG = r*G + c*xG_cleared
    let r_g = point_native::scalar_mul(&base, r);
    let c_xg = point_native::scalar_mul(&x_g_cleared, c);
    let v_g = point_native::add_points(&r_g, &c_xg);

    // Reconstruct vH = r*H + c*xH_cleared
    let r_h = point_native::scalar_mul(h, r);
    let c_xh = point_native::scalar_mul(&x_h_cleared, c);
    let v_h = point_native::add_points(&r_h, &c_xh);

    // Convert to affine for hashing
    let (base_x, base_y) = base.to_affine(&modulus);
    let (xg_x, xg_y) = x_g_cleared.to_affine(&modulus);
    let (vg_x, vg_y) = v_g.to_affine(&modulus);
    let (vh_x, vh_y) = v_h.to_affine(&modulus);
    let (h_x, h_y) = h.to_affine(&modulus);
    let (xh_x, xh_y) = x_h_cleared.to_affine(&modulus);

    // Recompute hash
    let hash_inputs = vec![
        base_x, base_y, xg_x, xg_y, vg_x, vg_y, vh_x, vh_y, h_x, h_y, xh_x, xh_y,
    ];

    let expected_c = hash_to_scalar(&hash_inputs);

    // Check c == expected_c
    c.limbs == expected_c.limbs
}

/// Hash multiple Field256 values to a scalar using Poseidon2.
///
/// This hashes all the M31 limbs and expands the result to a full scalar
/// by hashing with different domain separators.
fn hash_to_scalar(inputs: &[BigInt256]) -> BigInt256 {
    // Generate 9 limbs by hashing with different domain separators
    // The index is prepended to ensure each call produces different output
    let mut result_limbs = [0u32; 9];

    for (i, limb) in result_limbs.iter_mut().enumerate() {
        // Create deterministic input: [index, ...original_inputs]
        let mut extended_input: Vec<BigInt256> = Vec::with_capacity(inputs.len() + 1);
        extended_input.push(BigInt256::from_limbs([i as u32, 0, 0, 0, 0, 0, 0, 0, 0]));
        extended_input.extend(inputs.iter().cloned());

        let hash = hash_field256_native(&extended_input);
        *limb = hash.0 & 0x1FFFFFFF;
    }

    // Reduce modulo scalar order
    let mut result = BigInt256::from_limbs(result_limbs);
    let order = scalar_order();
    while result.cmp(&order) >= 0 {
        let (diff, _) = result.sub_no_reduce(&order);
        result = diff;
    }

    result
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
        let two = BigInt256::from_limbs([2, 0, 0, 0, 0, 0, 0, 0, 0]);
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
        let eight = BigInt256::from_limbs([8, 0, 0, 0, 0, 0, 0, 0, 0]);
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
        let eight = BigInt256::from_limbs([8, 0, 0, 0, 0, 0, 0, 0, 0]);
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
        let eight = BigInt256::from_limbs([8, 0, 0, 0, 0, 0, 0, 0, 0]);

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
        let one = BigInt256::from_limbs([1, 0, 0, 0, 0, 0, 0, 0, 0]);

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
        let two = BigInt256::from_limbs([2, 0, 0, 0, 0, 0, 0, 0, 0]);

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
        let eight = BigInt256::from_limbs([8, 0, 0, 0, 0, 0, 0, 0, 0]);
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

        let a = BigInt256::from_limbs([8, 0, 0, 0, 0, 0, 0, 0, 0]); // Use 8 like cofactor
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
        let eight = BigInt256::from_limbs([8, 0, 0, 0, 0, 0, 0, 0, 0]);
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
        let eight = BigInt256::from_limbs([8, 0, 0, 0, 0, 0, 0, 0, 0]);
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
    fn test_prove_verify_dleq() {
        let mut rng = ChaCha20Rng::seed_from_u64(12345);

        // Generate a random secret
        let x = random_scalar(&mut rng);
        println!("x = {:?}", x.limbs);

        // Use a random point H (would be client's masked point in practice)
        let h_scalar = random_scalar(&mut rng);
        let base = base_point();
        let h = point_native::scalar_mul(&base, &h_scalar);
        println!("h.x = {:?}", h.x.limbs);

        // Compute xG and xH - these should match what prove_dleq computes internally
        let x_g = point_native::scalar_mul(&base, &x);
        let x_h = point_native::scalar_mul(&h, &x);
        println!("x_g.x = {:?}", x_g.x.limbs);
        println!("x_h.x = {:?}", x_h.x.limbs);

        // Generate DLEQ proof
        let proof = prove_dleq(&mut rng, &x, &h);
        assert!(proof.is_some());

        let (c, r) = proof.unwrap();
        println!("c = {:?}", c.limbs);
        println!("r = {:?}", r.limbs);

        // Verify proof
        let valid = verify_dleq(&c, &r, &x_g, &x_h, &h);
        println!("valid = {}", valid);
        assert!(valid, "DLEQ proof should be valid");
    }

    #[test]
    fn test_dleq_invalid_proof() {
        let mut rng = ChaCha20Rng::seed_from_u64(12345);

        let x = random_scalar(&mut rng);
        let h_scalar = random_scalar(&mut rng);
        let base = base_point();

        let h = point_native::scalar_mul(&base, &h_scalar);
        let x_g = point_native::scalar_mul(&base, &x);
        let x_h = point_native::scalar_mul(&h, &x);

        let (c, _r) = prove_dleq(&mut rng, &x, &h).unwrap();

        // Use wrong r value
        let wrong_r = random_scalar(&mut rng);
        let valid = verify_dleq(&c, &wrong_r, &x_g, &x_h, &h);
        assert!(!valid, "DLEQ proof with wrong r should be invalid");
    }
}
