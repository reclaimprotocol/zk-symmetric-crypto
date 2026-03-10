//! Distributed Key Generation for TOPRF.
//!
//! Implements Shamir's Secret Sharing over the Baby Jubjub scalar field.

use rand::Rng;

use super::{Share, SharedKey};
use crate::babyjub::field256::gen::{scalar_order, BigInt256};
use crate::babyjub::field256::N_LIMBS;
use crate::babyjub::point::gen::native as point_native;
use crate::babyjub::point::base_point;

/// Generate a random scalar in the Baby Jubjub scalar field.
pub fn random_scalar<R: Rng>(rng: &mut R) -> BigInt256 {
    let order = scalar_order();
    let mut limbs = [0u32; N_LIMBS];

    // Generate random limbs (16-bit each)
    for limb in &mut limbs {
        *limb = rng.gen::<u32>() & 0xFFFF; // 16-bit limbs
    }

    // Reduce modulo scalar order
    let mut result = BigInt256::from_limbs(limbs);

    // Simple reduction: if >= order, subtract order
    loop {
        if result.cmp(&order) >= 0 {
            let (diff, _) = result.sub_no_reduce(&order);
            result = diff;
        } else {
            break;
        }
    }

    result
}

/// Generate a shared key with threshold Shamir secret sharing.
///
/// # Arguments
/// * `nodes` - Total number of key shares to create
/// * `threshold` - Minimum number of shares needed to reconstruct
///
/// # Returns
/// A SharedKey containing the server public key and all shares.
pub fn generate_shared_key<R: Rng>(rng: &mut R, nodes: usize, threshold: usize) -> SharedKey {
    assert!(threshold > 0, "Threshold must be positive");
    assert!(threshold <= nodes, "Threshold cannot exceed nodes");

    // Generate master secret key
    let master_secret = random_scalar(rng);

    // Compute server public key: G * master_secret
    let base = base_point();
    let server_public_key = point_native::scalar_mul(&base, &master_secret);

    // Create threshold shares
    let shares = create_shares(rng, nodes, threshold, &master_secret);

    SharedKey {
        nodes,
        threshold,
        server_public_key,
        shares,
    }
}

/// Create Shamir secret shares for a given secret.
///
/// Uses polynomial f(x) = a_0 + a_1*x + a_2*x^2 + ... + a_(k-1)*x^(k-1)
/// where a_0 = secret and k = threshold.
pub fn create_shares<R: Rng>(
    rng: &mut R,
    n: usize,
    threshold: usize,
    secret: &BigInt256,
) -> Vec<Share> {
    let order = scalar_order();

    // Generate random coefficients for polynomial (excluding a_0 which is the secret)
    let mut coefficients = vec![secret.clone()];
    for _ in 1..threshold {
        coefficients.push(random_scalar(rng));
    }

    // Evaluate polynomial at points 1, 2, ..., n
    let mut shares = Vec::with_capacity(n);

    for i in 1..=n {
        // Compute f(i) = a_0 + a_1*i + a_2*i^2 + ...
        let x = BigInt256::from_u32(i as u32);
        let private_key = evaluate_polynomial(&coefficients, &x, &order);

        // Compute public key: G * private_key
        let base = base_point();
        let public_key = point_native::scalar_mul(&base, &private_key);

        shares.push(Share {
            index: i,
            private_key,
            public_key,
        });
    }

    shares
}

/// Evaluate polynomial at a point.
/// f(x) = coefficients[0] + coefficients[1]*x + coefficients[2]*x^2 + ...
fn evaluate_polynomial(
    coefficients: &[BigInt256],
    x: &BigInt256,
    order: &BigInt256,
) -> BigInt256 {
    let mut result = BigInt256::zero();
    let mut x_power = BigInt256::one();

    for coeff in coefficients {
        // result += coeff * x^i
        let term = coeff.mul_mod(&x_power, order);
        result = result.add_mod(&term, order);

        // x_power *= x
        x_power = x_power.mul_mod(x, order);
    }

    result
}

/// Compute Lagrange coefficient for share reconstruction.
///
/// For share at index `idx` with other shares at indices `peers`,
/// returns the coefficient l_idx = product_{j in peers, j != idx} (j / (j - idx))
pub fn lagrange_coefficient(idx: usize, peers: &[usize]) -> BigInt256 {
    let order = scalar_order();
    let mut numerator = BigInt256::one();
    let mut denominator = BigInt256::one();

    for &j in peers {
        if j != idx {
            // numerator *= j
            let j_val = BigInt256::from_u32(j as u32);
            numerator = numerator.mul_mod(&j_val, &order);

            // denominator *= (j - idx)
            let idx_val = BigInt256::from_u32(idx as u32);
            let diff = if j > idx {
                let j_big = BigInt256::from_u32(j as u32);
                j_big.sub_mod(&idx_val, &order)
            } else {
                // j < idx, need to compute (j - idx) mod p = p - (idx - j)
                let idx_big = BigInt256::from_u32(idx as u32);
                let j_big = BigInt256::from_u32(j as u32);
                let diff_abs = idx_big.sub_mod(&j_big, &order);
                order.sub_mod(&diff_abs, &order)
            };
            denominator = denominator.mul_mod(&diff, &order);
        }
    }

    // Result = numerator * denominator^(-1)
    let denom_inv = denominator.inv_mod(&order).expect("Denominator should be non-zero");
    numerator.mul_mod(&denom_inv, &order)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;

    #[test]
    fn test_random_scalar() {
        let mut rng = ChaCha20Rng::seed_from_u64(12345);
        let scalar = random_scalar(&mut rng);

        // Should be non-zero
        assert!(!scalar.is_zero());

        // Should be less than scalar order
        let order = scalar_order();
        assert!(scalar.cmp(&order) < 0);
    }

    #[test]
    fn test_generate_shared_key() {
        let mut rng = ChaCha20Rng::seed_from_u64(12345);
        let key = generate_shared_key(&mut rng, 3, 2);

        assert_eq!(key.nodes, 3);
        assert_eq!(key.threshold, 2);
        assert_eq!(key.shares.len(), 3);

        // Each share should have correct index
        for (i, share) in key.shares.iter().enumerate() {
            assert_eq!(share.index, i + 1);
        }
    }

    #[test]
    fn test_lagrange_coefficient() {
        // For threshold=2 with peers [1, 2], compute coefficient for idx=1
        let peers = vec![1, 2];
        let coeff = lagrange_coefficient(1, &peers);

        // l_1 = 2 / (2 - 1) = 2
        let expected = BigInt256::from_u32(2);
        assert_eq!(coeff.limbs, expected.limbs);
    }

    #[test]
    fn test_polynomial_evaluation() {
        let order = scalar_order();

        // f(x) = 5 + 3x (secret=5, one random coeff=3)
        let coeffs = vec![
            BigInt256::from_u32(5),
            BigInt256::from_u32(3),
        ];

        // f(1) = 5 + 3*1 = 8
        let x1 = BigInt256::from_u32(1);
        let y1 = evaluate_polynomial(&coeffs, &x1, &order);
        assert_eq!(y1.limbs[0], 8);

        // f(2) = 5 + 3*2 = 11
        let x2 = BigInt256::from_u32(2);
        let y2 = evaluate_polynomial(&coeffs, &x2, &order);
        assert_eq!(y2.limbs[0], 11);
    }

    #[test]
    fn test_lagrange_reconstruction_scalar() {
        // Verify that Lagrange interpolation reconstructs the secret from shares
        let order = scalar_order();

        // f(x) = 5 + 3x (secret=5, coefficient=3)
        // f(1) = 8, f(2) = 11, f(3) = 14
        let secret = BigInt256::from_u32(5);
        let share1 = BigInt256::from_u32(8);
        let share2 = BigInt256::from_u32(11);
        let share3 = BigInt256::from_u32(14);

        // Reconstruct using shares 1 and 2
        let indices12 = vec![1, 2];
        let l1_12 = lagrange_coefficient(1, &indices12);
        let l2_12 = lagrange_coefficient(2, &indices12);
        let result12 = l1_12.mul_mod(&share1, &order).add_mod(&l2_12.mul_mod(&share2, &order), &order);

        println!("Using shares 1,2:");
        println!("  l1 = {:?}", l1_12.limbs);
        println!("  l2 = {:?}", l2_12.limbs);
        println!("  result = {:?}", result12.limbs);
        assert_eq!(result12.limbs, secret.limbs, "Shares (1,2) should reconstruct secret");

        // Reconstruct using shares 1 and 3
        let indices13 = vec![1, 3];
        let l1_13 = lagrange_coefficient(1, &indices13);
        let l3_13 = lagrange_coefficient(3, &indices13);
        let result13 = l1_13.mul_mod(&share1, &order).add_mod(&l3_13.mul_mod(&share3, &order), &order);

        println!("Using shares 1,3:");
        println!("  l1 = {:?}", l1_13.limbs);
        println!("  l3 = {:?}", l3_13.limbs);
        println!("  result = {:?}", result13.limbs);
        assert_eq!(result13.limbs, secret.limbs, "Shares (1,3) should reconstruct secret");

        // Reconstruct using shares 2 and 3
        let indices23 = vec![2, 3];
        let l2_23 = lagrange_coefficient(2, &indices23);
        let l3_23 = lagrange_coefficient(3, &indices23);
        let result23 = l2_23.mul_mod(&share2, &order).add_mod(&l3_23.mul_mod(&share3, &order), &order);

        println!("Using shares 2,3:");
        println!("  l2 = {:?}", l2_23.limbs);
        println!("  l3 = {:?}", l3_23.limbs);
        println!("  result = {:?}", result23.limbs);
        assert_eq!(result23.limbs, secret.limbs, "Shares (2,3) should reconstruct secret");
    }

    #[test]
    fn test_lagrange_reconstruction_with_random() {
        // Test with randomly generated shares
        let mut rng = ChaCha20Rng::seed_from_u64(12345);
        let order = scalar_order();

        // Generate a 2-of-3 threshold key
        let key = generate_shared_key(&mut rng, 3, 2);

        // Get the master secret by reconstructing from shares 1 and 2
        let indices12 = vec![1, 2];
        let l1 = lagrange_coefficient(1, &indices12);
        let l2 = lagrange_coefficient(2, &indices12);
        let master12 = l1.mul_mod(&key.shares[0].private_key, &order)
            .add_mod(&l2.mul_mod(&key.shares[1].private_key, &order), &order);

        // Reconstruct from shares 1 and 3
        let indices13 = vec![1, 3];
        let l1_13 = lagrange_coefficient(1, &indices13);
        let l3_13 = lagrange_coefficient(3, &indices13);
        let master13 = l1_13.mul_mod(&key.shares[0].private_key, &order)
            .add_mod(&l3_13.mul_mod(&key.shares[2].private_key, &order), &order);

        // Reconstruct from shares 2 and 3
        let indices23 = vec![2, 3];
        let l2_23 = lagrange_coefficient(2, &indices23);
        let l3_23 = lagrange_coefficient(3, &indices23);
        let master23 = l2_23.mul_mod(&key.shares[1].private_key, &order)
            .add_mod(&l3_23.mul_mod(&key.shares[2].private_key, &order), &order);

        println!("Reconstructed from (1,2): {:?}", master12.limbs);
        println!("Reconstructed from (1,3): {:?}", master13.limbs);
        println!("Reconstructed from (2,3): {:?}", master23.limbs);

        // All three should be equal
        assert_eq!(master12.limbs, master13.limbs, "Reconstruction from (1,2) and (1,3) should match");
        assert_eq!(master13.limbs, master23.limbs, "Reconstruction from (1,3) and (2,3) should match");
    }
}
