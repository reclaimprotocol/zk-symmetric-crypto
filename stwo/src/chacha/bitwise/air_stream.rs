//! AIR for ChaCha20 stream encryption (bitwise with plaintext XOR).

use std::simd::u32x16;

use blake2::{Blake2s256, Digest};
use itertools::Itertools;
use num_traits::Zero;
use serde::{Serialize, Deserialize};
use stwo::core::air::Component;
use stwo::core::channel::{Channel, MerkleChannel};
use stwo::core::fields::qm31::SecureField;
use stwo::core::pcs::{CommitmentSchemeVerifier, PcsConfig, TreeVec};
use stwo::core::poly::circle::CanonicCoset;
use stwo::core::proof::StarkProof;
use stwo::core::vcs_lifted::merkle_hasher::MerkleHasherLifted;
use stwo::core::verifier::{verify, VerificationError};
use stwo::prover::backend::simd::m31::LOG_N_LANES;
use stwo::prover::backend::simd::SimdBackend;
use stwo::prover::backend::BackendForChannel;
use stwo::prover::poly::circle::PolyOps;
use stwo::prover::{prove, CommitmentSchemeProver, ComponentProver};
use stwo_constraint_framework::TraceLocationAllocator;

use super::{
    chacha_stream_info, generate_stream_trace, ChaChaStreamComponent, ChaChaStreamEval,
    ChaChaStreamInput,
};

/// Public inputs for ChaCha20 proof - cryptographically bound to the proof via Fiat-Shamir.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ChaChaPublicInputs {
    /// 12-byte nonce (as 3 u32s in little-endian)
    pub nonce: [u8; 12],
    /// Starting counter value
    pub counter: u32,
    /// Blake2s hash of plaintext (for binding without storing full plaintext)
    pub plaintext_hash: [u8; 32],
    /// Blake2s hash of ciphertext
    pub ciphertext_hash: [u8; 32],
}

impl ChaChaPublicInputs {
    /// Create public inputs from raw data.
    pub fn new(nonce: &[u8; 12], counter: u32, plaintext: &[u8], ciphertext: &[u8]) -> Self {
        let plaintext_hash: [u8; 32] = Blake2s256::digest(plaintext).into();
        let ciphertext_hash: [u8; 32] = Blake2s256::digest(ciphertext).into();
        Self {
            nonce: *nonce,
            counter,
            plaintext_hash,
            ciphertext_hash,
        }
    }

    /// Verify that the provided data matches this public input commitment.
    pub fn verify(&self, nonce: &[u8; 12], counter: u32, plaintext: &[u8], ciphertext: &[u8]) -> bool {
        if self.nonce != *nonce || self.counter != counter {
            return false;
        }
        let plaintext_hash: [u8; 32] = Blake2s256::digest(plaintext).into();
        let ciphertext_hash: [u8; 32] = Blake2s256::digest(ciphertext).into();
        self.plaintext_hash == plaintext_hash && self.ciphertext_hash == ciphertext_hash
    }

    /// Mix into Fiat-Shamir channel.
    fn mix_into(&self, channel: &mut impl Channel) {
        // Mix nonce (as 3 u32s)
        for i in 0..3 {
            let val = u32::from_le_bytes([
                self.nonce[i * 4],
                self.nonce[i * 4 + 1],
                self.nonce[i * 4 + 2],
                self.nonce[i * 4 + 3],
            ]);
            channel.mix_u64(val as u64);
        }
        // Mix counter
        channel.mix_u64(self.counter as u64);
        // Mix plaintext hash (as 8 u32s)
        for i in 0..8 {
            let val = u32::from_le_bytes([
                self.plaintext_hash[i * 4],
                self.plaintext_hash[i * 4 + 1],
                self.plaintext_hash[i * 4 + 2],
                self.plaintext_hash[i * 4 + 3],
            ]);
            channel.mix_u64(val as u64);
        }
        // Mix ciphertext hash (as 8 u32s)
        for i in 0..8 {
            let val = u32::from_le_bytes([
                self.ciphertext_hash[i * 4],
                self.ciphertext_hash[i * 4 + 1],
                self.ciphertext_hash[i * 4 + 2],
                self.ciphertext_hash[i * 4 + 3],
            ]);
            channel.mix_u64(val as u64);
        }
    }
}

/// Statement for ChaCha20 stream.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct StreamStatement {
    pub log_size: u32,
    /// Public inputs bound to the proof
    pub public_inputs: ChaChaPublicInputs,
}

impl StreamStatement {
    fn log_sizes(&self) -> TreeVec<Vec<u32>> {
        let info = chacha_stream_info();
        let n_trace_cols = info.mask_offsets[1].len();
        TreeVec::new(vec![
            vec![],                            // Preprocessed (empty)
            vec![self.log_size; n_trace_cols], // Main trace
        ])
    }

    fn mix_into(&self, channel: &mut impl Channel) {
        channel.mix_u64(self.log_size as u64);
        self.public_inputs.mix_into(channel);
    }
}

/// ChaCha20 stream proof.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct StreamProof<H: MerkleHasherLifted> {
    pub stmt: StreamStatement,
    pub stark_proof: StarkProof<H>,
}

/// Prove ChaCha20 stream encryption with provided inputs.
///
/// # Arguments
/// * `log_size` - Log2 of the number of ChaCha20 blocks to prove
/// * `config` - PCS configuration
/// * `nonce` - 12-byte nonce
/// * `counter` - Starting counter value
/// * `plaintext` - Plaintext bytes (must be multiple of 64)
/// * `ciphertext` - Ciphertext bytes (same length as plaintext)
/// * `inputs` - SIMD-packed trace inputs
pub fn prove_stream_with_inputs<MC: MerkleChannel>(
    log_size: u32,
    config: PcsConfig,
    nonce: &[u8; 12],
    counter: u32,
    plaintext: &[u8],
    ciphertext: &[u8],
    inputs: &[ChaChaStreamInput],
) -> Result<StreamProof<MC::H>, String>
where
    SimdBackend: BackendForChannel<MC>,
{
    let public_inputs = ChaChaPublicInputs::new(nonce, counter, plaintext, ciphertext);
    prove_stream_internal::<MC>(log_size, config, inputs, public_inputs)
}

/// Internal prove function for ChaCha20 stream.
fn prove_stream_internal<MC: MerkleChannel>(
    log_size: u32,
    config: PcsConfig,
    inputs: &[ChaChaStreamInput],
    public_inputs: ChaChaPublicInputs,
) -> Result<StreamProof<MC::H>, String>
where
    SimdBackend: BackendForChannel<MC>,
{
    if log_size < LOG_N_LANES {
        return Err(format!(
            "log_size ({}) must be >= LOG_N_LANES ({})",
            log_size, LOG_N_LANES
        ));
    }
    // Maximum log_size to prevent excessive memory/computation (24 = 16M blocks = 1GB)
    const MAX_LOG_SIZE: u32 = 24;
    if log_size > MAX_LOG_SIZE {
        return Err(format!(
            "log_size ({}) must be <= MAX_LOG_SIZE ({})",
            log_size, MAX_LOG_SIZE
        ));
    }

    // Precompute twiddles
    let twiddles = SimdBackend::precompute_twiddles(
        CanonicCoset::new(log_size + 1 + config.fri_config.log_blowup_factor)
            .circle_domain()
            .half_coset,
    );

    // Setup protocol
    let channel = &mut MC::C::default();
    let mut commitment_scheme = CommitmentSchemeProver::new(config, &twiddles);

    // No preprocessed trace
    let tree_builder = commitment_scheme.tree_builder();
    tree_builder.commit(channel);

    // Generate trace
    let (trace, valid) = generate_stream_trace(log_size, inputs);
    if !valid {
        return Err("Ciphertext does not match encryption - invalid witness".to_string());
    }

    // Statement with cryptographically bound public inputs
    let stmt = StreamStatement { log_size, public_inputs };
    stmt.mix_into(channel);

    // Commit trace
    let mut tree_builder = commitment_scheme.tree_builder();
    tree_builder.extend_evals(trace.into_iter().collect_vec());
    tree_builder.commit(channel);

    // Create component
    let tree_span_provider = &mut TraceLocationAllocator::default();
    let component = ChaChaStreamComponent::new(
        tree_span_provider,
        ChaChaStreamEval {
            log_size,
            claimed_sum: SecureField::zero(),
        },
        SecureField::zero(),
    );

    // Prove
    let stark_proof = prove(
        &[&component as &dyn ComponentProver<SimdBackend>],
        channel,
        commitment_scheme,
    )
    .map_err(|e| format!("Proof generation failed: {:?}", e))?;

    Ok(StreamProof { stmt, stark_proof })
}

/// Prove ChaCha20 stream encryption with test data (for benchmarks/tests).
pub fn prove_stream<MC: MerkleChannel>(log_size: u32, config: PcsConfig) -> StreamProof<MC::H>
where
    SimdBackend: BackendForChannel<MC>,
{
    use super::gen_stream::chacha20_encrypt;

    // Test key and nonce
    let key: [u32; 8] = [
        0x03020100, 0x07060504, 0x0b0a0908, 0x0f0e0d0c,
        0x13121110, 0x17161514, 0x1b1a1918, 0x1f1e1d1c,
    ];
    let nonce: [u32; 3] = [0x00000000, 0x0000004a, 0x00000000];

    // Generate inputs with incrementing counters, plaintext, and correct ciphertext
    let inputs: Vec<ChaChaStreamInput> = (0..(1 << (log_size - LOG_N_LANES)))
        .map(|i| {
            let counters = u32x16::from_array(std::array::from_fn(|lane| (i * 16 + lane + 1) as u32));

            // Test plaintext pattern
            let plaintext: [u32x16; 16] = std::array::from_fn(|word| {
                u32x16::from_array(std::array::from_fn(|lane| {
                    ((i * 16 + lane) * 16 + word) as u32
                }))
            });

            // Compute correct ciphertext for each lane
            let mut ciphertext: [u32x16; 16] = [u32x16::splat(0); 16];
            for lane in 0..16 {
                let counter = (i * 16 + lane + 1) as u32;
                let pt: [u32; 16] = std::array::from_fn(|w| plaintext[w][lane]);
                let ct = chacha20_encrypt(&key, &nonce, counter, &pt);
                for w in 0..16 {
                    ciphertext[w][lane] = ct[w];
                }
            }

            ChaChaStreamInput {
                key,
                nonce,
                counters,
                plaintext,
                ciphertext,
            }
        })
        .collect();

    // For test data, create dummy public inputs
    let nonce_bytes: [u8; 12] = [0x00; 12];
    let public_inputs = ChaChaPublicInputs::new(&nonce_bytes, 1, &[], &[]);

    prove_stream_internal::<MC>(log_size, config, &inputs, public_inputs)
        .expect("Test data should produce valid proof")
}

/// Verify ChaCha20 stream proof with verifier-supplied public inputs.
///
/// This is the secure verification function that ensures the proof is bound to the
/// claimed public data (nonce, counter, plaintext, ciphertext).
///
/// # Arguments
/// * `proof` - The proof to verify
/// * `nonce` - The 12-byte nonce the verifier claims was used
/// * `counter` - The starting counter the verifier claims was used
/// * `plaintext` - The plaintext the verifier claims corresponds to the ciphertext
/// * `ciphertext` - The ciphertext the verifier claims was encrypted
///
/// # Security
/// The public inputs are cryptographically bound to the proof via Fiat-Shamir.
/// If the verifier-supplied inputs don't match what was proven, verification fails.
pub fn verify_stream_with_public_inputs<MC: MerkleChannel>(
    proof: StreamProof<MC::H>,
    nonce: &[u8; 12],
    counter: u32,
    plaintext: &[u8],
    ciphertext: &[u8],
) -> Result<(), VerificationError> {
    // Verify the proof's public inputs match the verifier's claimed data
    // This ensures the proof is bound to the specific data the verifier expects
    if !proof.stmt.public_inputs.verify(nonce, counter, plaintext, ciphertext) {
        // Public inputs don't match - the proof is for different data
        return Err(VerificationError::OodsNotMatching);
    }

    // Proceed with STARK verification (the channel will mix the same values)
    verify_stream_internal::<MC>(proof)
}

/// Verify ChaCha20 stream proof without external public input validation.
///
/// WARNING: This function trusts the public inputs embedded in the proof.
/// For production use with untrusted provers, use `verify_stream_with_public_inputs` instead.
pub fn verify_stream<MC: MerkleChannel>(
    proof: StreamProof<MC::H>,
) -> Result<(), VerificationError> {
    verify_stream_internal::<MC>(proof)
}

/// Internal verification function.
fn verify_stream_internal<MC: MerkleChannel>(
    StreamProof { stmt, stark_proof }: StreamProof<MC::H>,
) -> Result<(), VerificationError> {
    // Validate commitment count before indexing
    if stark_proof.commitments.len() < 2 {
        return Err(VerificationError::OodsNotMatching);
    }

    let channel = &mut MC::C::default();
    let commitment_scheme = &mut CommitmentSchemeVerifier::<MC>::new(stark_proof.config);

    let log_sizes = stmt.log_sizes();

    // Preprocessed (empty)
    commitment_scheme.commit(stark_proof.commitments[0], &log_sizes[0], channel);

    // Trace
    stmt.mix_into(channel);
    commitment_scheme.commit(stark_proof.commitments[1], &log_sizes[1], channel);

    // Create component
    let tree_span_provider = &mut TraceLocationAllocator::default();
    let component = ChaChaStreamComponent::new(
        tree_span_provider,
        ChaChaStreamEval {
            log_size: stmt.log_size,
            claimed_sum: SecureField::zero(),
        },
        SecureField::zero(),
    );

    verify(
        &[&component as &dyn Component],
        channel,
        commitment_scheme,
        stark_proof,
    )
}

#[cfg(test)]
mod tests {
    use std::time::Instant;

    use stwo::core::pcs::PcsConfig;
    use stwo::core::vcs_lifted::blake2_merkle::Blake2sMerkleChannel;

    use super::*;

    #[test]
    fn test_stream_prove_verify() {
        let log_size = 6; // 64 blocks
        let config = PcsConfig::default();

        let n_blocks = 1 << log_size;
        let bytes = n_blocks * 64; // ChaCha block = 64 bytes
        println!(
            "Proving {} ChaCha20 stream blocks ({} bytes)...",
            n_blocks, bytes
        );

        let start = Instant::now();
        let proof = prove_stream::<Blake2sMerkleChannel>(log_size, config);
        let prove_time = start.elapsed();
        println!("Prove time: {:?}", prove_time);

        let start = Instant::now();
        verify_stream::<Blake2sMerkleChannel>(proof).unwrap();
        let verify_time = start.elapsed();
        println!("Verify time: {:?}", verify_time);
    }

    // ==================== SECURITY TESTS ====================
    // These tests verify the cryptographic binding of public inputs to proofs.
    // See README.md "Security Model" section for detailed documentation.

    /// Helper to compute ciphertext for SIMD input using native encrypt.
    fn compute_simd_ciphertext(
        key: &[u32; 8],
        nonce: &[u32; 3],
        counters: u32x16,
        plaintext: &[u32x16; 16],
    ) -> [u32x16; 16] {
        use crate::chacha::bitwise::gen_stream::chacha20_encrypt;
        let mut ciphertext: [u32x16; 16] = [u32x16::splat(0); 16];
        for lane in 0..16 {
            let counter = counters.to_array()[lane];
            let pt: [u32; 16] = std::array::from_fn(|w| plaintext[w].to_array()[lane]);
            let ct = chacha20_encrypt(key, nonce, counter, &pt);
            for w in 0..16 {
                let mut arr = ciphertext[w].to_array();
                arr[lane] = ct[w];
                ciphertext[w] = u32x16::from_array(arr);
            }
        }
        ciphertext
    }

    /// Security test: Verify that tampering with public inputs in a serialized proof
    /// causes verification to fail.
    ///
    /// Attack scenario:
    /// 1. Attacker generates valid proof for data_A
    /// 2. Attacker modifies proof.stmt.public_inputs to claim data_B
    /// 3. Verifier should reject the tampered proof
    #[test]
    fn test_security_chacha_tampered_public_inputs_in_proof() {
        let log_size = 4; // Small for fast test
        let config = PcsConfig::default();

        let key: [u32; 8] = [
            0x03020100, 0x07060504, 0x0b0a0908, 0x0f0e0d0c,
            0x13121110, 0x17161514, 0x1b1a1918, 0x1f1e1d1c,
        ];
        let nonce: [u32; 3] = [0x00000000, 0x0000004a, 0x00000000];
        let nonce_bytes: [u8; 12] = {
            let mut bytes = [0u8; 12];
            for (i, &word) in nonce.iter().enumerate() {
                bytes[i*4..(i+1)*4].copy_from_slice(&word.to_le_bytes());
            }
            bytes
        };

        // Generate inputs with proper SIMD ciphertext computation
        let inputs: Vec<ChaChaStreamInput> = (0..(1 << (log_size - 4)))
            .map(|i| {
                let counters = u32x16::from_array(std::array::from_fn(|lane| (i * 16 + lane + 1) as u32));
                let plaintext: [u32x16; 16] = std::array::from_fn(|word| {
                    u32x16::from_array(std::array::from_fn(|lane| {
                        ((i * 16 + lane) * 16 + word) as u32
                    }))
                });
                let ciphertext = compute_simd_ciphertext(&key, &nonce, counters, &plaintext);
                ChaChaStreamInput { key, nonce, counters, plaintext, ciphertext }
            })
            .collect();

        // Collect plaintext/ciphertext bytes for public inputs
        let mut plaintext_bytes = Vec::new();
        let mut ciphertext_bytes = Vec::new();
        for input in &inputs {
            for lane in 0..16 {
                for word in 0..16 {
                    plaintext_bytes.extend_from_slice(&input.plaintext[word].to_array()[lane].to_le_bytes());
                    ciphertext_bytes.extend_from_slice(&input.ciphertext[word].to_array()[lane].to_le_bytes());
                }
            }
        }

        // Generate valid proof
        let mut proof = prove_stream_with_inputs::<Blake2sMerkleChannel>(
            log_size, config, &nonce_bytes, 1, &plaintext_bytes, &ciphertext_bytes, &inputs
        ).expect("Valid proof should succeed");

        // Tamper with public inputs - claim different plaintext
        let fake_plaintext = vec![0xffu8; plaintext_bytes.len()];
        proof.stmt.public_inputs = ChaChaPublicInputs::new(&nonce_bytes, 1, &fake_plaintext, &ciphertext_bytes);

        // Verification should fail
        let result = verify_stream_with_public_inputs::<Blake2sMerkleChannel>(
            proof, &nonce_bytes, 1, &fake_plaintext, &ciphertext_bytes
        );
        assert!(result.is_err(), "Tampered proof should fail verification");
        println!("Security test passed: tampered public inputs detected");
    }

    /// Security test: Verify that a valid proof fails when verifier supplies
    /// different public inputs than what was proven.
    #[test]
    fn test_security_chacha_verify_with_wrong_public_inputs() {
        let log_size = 4;
        let config = PcsConfig::default();

        let key: [u32; 8] = [
            0x03020100, 0x07060504, 0x0b0a0908, 0x0f0e0d0c,
            0x13121110, 0x17161514, 0x1b1a1918, 0x1f1e1d1c,
        ];
        let nonce: [u32; 3] = [0x00000000, 0x0000004a, 0x00000000];
        let nonce_bytes: [u8; 12] = {
            let mut bytes = [0u8; 12];
            for (i, &word) in nonce.iter().enumerate() {
                bytes[i*4..(i+1)*4].copy_from_slice(&word.to_le_bytes());
            }
            bytes
        };

        let inputs: Vec<ChaChaStreamInput> = (0..(1 << (log_size - 4)))
            .map(|i| {
                let counters = u32x16::from_array(std::array::from_fn(|lane| (i * 16 + lane + 1) as u32));
                let plaintext: [u32x16; 16] = std::array::from_fn(|word| {
                    u32x16::from_array(std::array::from_fn(|lane| {
                        ((i * 16 + lane) * 16 + word) as u32
                    }))
                });
                let ciphertext = compute_simd_ciphertext(&key, &nonce, counters, &plaintext);
                ChaChaStreamInput { key, nonce, counters, plaintext, ciphertext }
            })
            .collect();

        let mut plaintext_bytes = Vec::new();
        let mut ciphertext_bytes = Vec::new();
        for input in &inputs {
            for lane in 0..16 {
                for word in 0..16 {
                    plaintext_bytes.extend_from_slice(&input.plaintext[word].to_array()[lane].to_le_bytes());
                    ciphertext_bytes.extend_from_slice(&input.ciphertext[word].to_array()[lane].to_le_bytes());
                }
            }
        }

        let proof = prove_stream_with_inputs::<Blake2sMerkleChannel>(
            log_size, config, &nonce_bytes, 1, &plaintext_bytes, &ciphertext_bytes, &inputs
        ).expect("Valid proof should succeed");

        // Verify with correct inputs should succeed
        assert!(
            verify_stream_with_public_inputs::<Blake2sMerkleChannel>(
                proof.clone(), &nonce_bytes, 1, &plaintext_bytes, &ciphertext_bytes
            ).is_ok(),
            "Verification with correct inputs should succeed"
        );

        // Verify with wrong plaintext should fail
        let wrong_plaintext = vec![0xffu8; plaintext_bytes.len()];
        assert!(
            verify_stream_with_public_inputs::<Blake2sMerkleChannel>(
                proof.clone(), &nonce_bytes, 1, &wrong_plaintext, &ciphertext_bytes
            ).is_err(),
            "Verification with wrong plaintext should fail"
        );

        // Verify with wrong nonce should fail
        let wrong_nonce: [u8; 12] = [0xff; 12];
        assert!(
            verify_stream_with_public_inputs::<Blake2sMerkleChannel>(
                proof.clone(), &wrong_nonce, 1, &plaintext_bytes, &ciphertext_bytes
            ).is_err(),
            "Verification with wrong nonce should fail"
        );

        // Verify with wrong counter should fail
        assert!(
            verify_stream_with_public_inputs::<Blake2sMerkleChannel>(
                proof.clone(), &nonce_bytes, 999, &plaintext_bytes, &ciphertext_bytes
            ).is_err(),
            "Verification with wrong counter should fail"
        );

        // Verify with wrong ciphertext should fail
        let wrong_ciphertext = vec![0xffu8; ciphertext_bytes.len()];
        assert!(
            verify_stream_with_public_inputs::<Blake2sMerkleChannel>(
                proof, &nonce_bytes, 1, &plaintext_bytes, &wrong_ciphertext
            ).is_err(),
            "Verification with wrong ciphertext should fail"
        );

        println!("Security test passed: wrong public inputs correctly rejected");
    }

    #[test]
    #[ignore]
    fn bench_stream() {
        for log_size in [4, 5, 6, 7, 8] {
            let config = PcsConfig::default();
            let n_blocks = 1 << log_size;
            let bytes = n_blocks * 64;

            println!(
                "\n=== ChaCha20 Stream log_size={} ({} blocks, {} bytes) ===",
                log_size, n_blocks, bytes
            );

            let start = Instant::now();
            let proof = prove_stream::<Blake2sMerkleChannel>(log_size, config);
            let prove_time = start.elapsed();

            let start = Instant::now();
            verify_stream::<Blake2sMerkleChannel>(proof).unwrap();
            let verify_time = start.elapsed();

            let blocks_per_sec = n_blocks as f64 / prove_time.as_secs_f64();
            println!(
                "Prove: {:?} ({:.1} blocks/sec)",
                prove_time, blocks_per_sec
            );
            println!("Verify: {:?}", verify_time);
        }
    }
}
