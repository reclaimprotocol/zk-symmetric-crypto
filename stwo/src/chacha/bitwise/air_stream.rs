//! AIR for ChaCha20 stream encryption (bitwise with plaintext XOR).

use std::simd::u32x16;

use crate::public_inputs::{preprocessed_root, public_column_ids, public_trace};
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

/// Public inputs for ChaCha20 proof, bound to trace cells by public columns.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ChaChaPublicInputs {
    /// 12-byte nonce (as 3 u32s in little-endian)
    pub nonce: [u8; 12],
    /// Starting counter value
    pub counter: u32,
    /// Blake2s digest of plaintext, included in the transcript
    pub plaintext_hash: [u8; 32],
    /// Blake2s hash of ciphertext
    pub ciphertext_hash: [u8; 32],
    /// Public bytes needed to reconstruct the preprocessed commitment.
    pub plaintext: Vec<u8>,
    pub ciphertext: Vec<u8>,
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
            plaintext: plaintext.to_vec(),
            ciphertext: ciphertext.to_vec(),
        }
    }

    /// Verify that the provided data matches this public input commitment.
    pub fn verify(&self, nonce: &[u8; 12], counter: u32, plaintext: &[u8], ciphertext: &[u8]) -> bool {
        if self.nonce != *nonce || self.counter != counter {
            return false;
        }
        let plaintext_hash: [u8; 32] = Blake2s256::digest(plaintext).into();
        let ciphertext_hash: [u8; 32] = Blake2s256::digest(ciphertext).into();
        self.plaintext == plaintext
            && self.ciphertext == ciphertext
            && self.plaintext_hash == plaintext_hash
            && self.ciphertext_hash == ciphertext_hash
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
            vec![self.log_size; public_column_ids(64).len()], // Public columns
            vec![self.log_size; n_trace_cols],                // Main trace
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

    let preprocessed = public_trace(
        log_size,
        64,
        &public_inputs.nonce,
        public_inputs.counter,
        &public_inputs.plaintext,
        &public_inputs.ciphertext,
    )?;
    let mut tree_builder = commitment_scheme.tree_builder();
    tree_builder.extend_evals(preprocessed);
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
    let tree_span_provider =
        &mut TraceLocationAllocator::new_with_preprocessed_columns(&public_column_ids(64));
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

    let nonce_bytes: [u8; 12] = std::array::from_fn(|byte| nonce[byte / 4].to_le_bytes()[byte % 4]);
    let mut plaintext = Vec::new();
    let mut ciphertext = Vec::new();
    for input in &inputs {
        for lane in 0..16 {
            for word in 0..16 {
                plaintext.extend_from_slice(&input.plaintext[word][lane].to_le_bytes());
                ciphertext.extend_from_slice(&input.ciphertext[word][lane].to_le_bytes());
            }
        }
    }
    let public_inputs = ChaChaPublicInputs::new(&nonce_bytes, 1, &plaintext, &ciphertext);

    prove_stream_internal::<MC>(log_size, config, &inputs, public_inputs)
        .expect("Test data should produce valid proof")
}

/// Validate that the proof's PCS config meets minimum security requirements.
fn validate_pcs_config(
    proof_config: &PcsConfig,
    min_config: &PcsConfig,
) -> Result<(), VerificationError> {
    if proof_config.pow_bits < min_config.pow_bits {
        return Err(VerificationError::InvalidStructure(
            format!(
                "Proof pow_bits ({}) below minimum ({})",
                proof_config.pow_bits, min_config.pow_bits
            )
        ));
    }
    if proof_config.fri_config.log_blowup_factor < min_config.fri_config.log_blowup_factor {
        return Err(VerificationError::InvalidStructure(
            format!(
                "Proof log_blowup_factor ({}) below minimum ({})",
                proof_config.fri_config.log_blowup_factor,
                min_config.fri_config.log_blowup_factor
            )
        ));
    }
    if proof_config.fri_config.n_queries < min_config.fri_config.n_queries {
        return Err(VerificationError::InvalidStructure(
            format!(
                "Proof n_queries ({}) below minimum ({})",
                proof_config.fri_config.n_queries,
                min_config.fri_config.n_queries
            )
        ));
    }
    Ok(())
}

/// Verify ChaCha20 stream proof with verifier-supplied public inputs and config validation.
///
/// This is the secure verification function that ensures the proof is bound to the
/// claimed public data (nonce, counter, plaintext, ciphertext) and uses acceptable
/// security parameters.
///
/// # Arguments
/// * `proof` - The proof to verify
/// * `min_config` - Minimum acceptable PCS config (rejects proofs with weaker settings)
/// * `nonce` - The 12-byte nonce the verifier claims was used
/// * `counter` - The starting counter the verifier claims was used
/// * `plaintext` - The plaintext the verifier claims corresponds to the ciphertext
/// * `ciphertext` - The ciphertext the verifier claims was encrypted
///
/// # Security
/// - The proof's PCS config is validated against min_config before any verifier state is created
/// - AIR constraints bind trace bytes to verifier-reconstructed public columns
/// - If the verifier-supplied inputs don't match what was proven, verification fails
pub fn verify_stream_with_public_inputs<MC: MerkleChannel>(
    proof: StreamProof<MC::H>,
    min_config: &PcsConfig,
    nonce: &[u8; 12],
    counter: u32,
    plaintext: &[u8],
    ciphertext: &[u8],
) -> Result<(), VerificationError>
where
    SimdBackend: BackendForChannel<MC>,
{
    // SECURITY: Validate proof's config meets minimum requirements BEFORE creating verifier state
    validate_pcs_config(&proof.stark_proof.config, min_config)?;

    // Verify the proof's public inputs match the verifier's claimed data
    // This ensures the proof is bound to the specific data the verifier expects
    if !proof.stmt.public_inputs.verify(nonce, counter, plaintext, ciphertext) {
        // Public inputs don't match - the proof is for different data
        return Err(VerificationError::OodsNotMatching);
    }

    // Proceed with STARK verification (the channel will mix the same values)
    verify_stream_internal::<MC>(proof)
}

/// Verify ChaCha20 stream proof with config validation but without external public input validation.
///
/// WARNING: This function trusts the public inputs embedded in the proof.
/// For production use with untrusted provers, use `verify_stream_with_public_inputs` instead.
///
/// # Arguments
/// * `proof` - The proof to verify
/// * `min_config` - Minimum acceptable PCS config (rejects proofs with weaker settings)
pub fn verify_stream<MC: MerkleChannel>(
    proof: StreamProof<MC::H>,
    min_config: &PcsConfig,
) -> Result<(), VerificationError>
where
    SimdBackend: BackendForChannel<MC>,
{
    // SECURITY: Validate proof's config meets minimum requirements BEFORE creating verifier state
    validate_pcs_config(&proof.stark_proof.config, min_config)?;

    verify_stream_internal::<MC>(proof)
}

/// Internal verification function.
fn verify_stream_internal<MC: MerkleChannel>(
    StreamProof { stmt, stark_proof }: StreamProof<MC::H>,
) -> Result<(), VerificationError>
where
    SimdBackend: BackendForChannel<MC>,
{
    // Validate commitment count before indexing
    if stark_proof.commitments.len() < 2 {
        return Err(VerificationError::OodsNotMatching);
    }

    let inputs = &stmt.public_inputs;
    if !inputs.verify(
        &inputs.nonce,
        inputs.counter,
        &inputs.plaintext,
        &inputs.ciphertext,
    ) {
        return Err(VerificationError::OodsNotMatching);
    }
    let preprocessed = public_trace(
        stmt.log_size,
        64,
        &inputs.nonce,
        inputs.counter,
        &inputs.plaintext,
        &inputs.ciphertext,
    )
    .map_err(VerificationError::InvalidStructure)?;
    if stark_proof.commitments[0]
        != preprocessed_root::<MC>(stmt.log_size, stark_proof.config, preprocessed)
    {
        return Err(VerificationError::OodsNotMatching);
    }

    let channel = &mut MC::C::default();
    let commitment_scheme = &mut CommitmentSchemeVerifier::<MC>::new(stark_proof.config);

    let log_sizes = stmt.log_sizes();

    // Preprocessed public columns, authenticated against verifier-reconstructed bytes.
    commitment_scheme.commit(stark_proof.commitments[0], &log_sizes[0], channel);

    // Trace
    stmt.mix_into(channel);
    commitment_scheme.commit(stark_proof.commitments[1], &log_sizes[1], channel);

    // Create component
    let tree_span_provider =
        &mut TraceLocationAllocator::new_with_preprocessed_columns(&public_column_ids(64));
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
        verify_stream::<Blake2sMerkleChannel>(proof, &PcsConfig::default()).unwrap();
        let verify_time = start.elapsed();
        println!("Verify time: {:?}", verify_time);
    }

    // ==================== SECURITY TESTS ====================
    // These tests verify the cryptographic binding of public inputs to proofs.
    // See README.md "Security Model" section for detailed documentation.

    #[test]
    fn test_security_chacha_forged_statement_before_proving() {
        let key = [0x12345678; 8];
        let nonce = [0x87654321; 3];
        let counters = u32x16::from_array(std::array::from_fn(|lane| lane as u32 + 1));
        let plaintext = [u32x16::splat(0); 16];
        let ciphertext = compute_simd_ciphertext(&key, &nonce, counters, &plaintext);
        let inputs = [ChaChaStreamInput {
            key,
            nonce,
            counters,
            plaintext,
            ciphertext,
        }];
        let fake_nonce = [0xab; 12];
        let fake_plaintext = vec![0x41; 16 * 64];
        let fake_ciphertext = vec![0x42; 16 * 64];

        // Choose the false statement BEFORE deriving challenges. Post-hoc
        // statement tampering does not exercise this attack.
        let proof = prove_stream_with_inputs::<Blake2sMerkleChannel>(
            4,
            PcsConfig::default(),
            &fake_nonce,
            99,
            &fake_plaintext,
            &fake_ciphertext,
            &inputs,
        );
        let proof = match proof {
            Ok(proof) => proof,
            Err(error) => {
                assert!(error.contains("ConstraintsNotSatisfied"), "{error}");
                return;
            }
        };
        let result = verify_stream_with_public_inputs::<Blake2sMerkleChannel>(
            proof,
            &PcsConfig::default(),
            &fake_nonce,
            99,
            &fake_plaintext,
            &fake_ciphertext,
        );
        assert!(
            result.is_err(),
            "Verifier accepted an unrelated trace for a forged statement"
        );
    }

    fn stream_fixture(n_blocks: usize) -> (ChaChaPublicInputs, Vec<ChaChaStreamInput>) {
        let key = [0x12345678; 8];
        let nonce: [u32; 3] = [0x87654321, 0x11223344, 0xaabbccdd];
        let counter = 0x01020304;
        let inputs: Vec<_> = (0..n_blocks.div_ceil(16))
            .map(|row| {
                let counters = u32x16::from_array(std::array::from_fn(|lane| {
                    counter + (row * 16 + lane) as u32
                }));
                let plaintext = std::array::from_fn(|word| {
                    u32x16::from_array(std::array::from_fn(|lane| {
                        if row * 16 + lane < n_blocks {
                            (row * 256 + lane * 16 + word) as u32
                        } else {
                            0
                        }
                    }))
                });
                let ciphertext = compute_simd_ciphertext(&key, &nonce, counters, &plaintext);
                ChaChaStreamInput {
                    key,
                    nonce,
                    counters,
                    plaintext,
                    ciphertext,
                }
            })
            .collect();
        let mut plaintext = Vec::new();
        let mut ciphertext = Vec::new();
        for block in 0..n_blocks {
            let input = &inputs[block / 16];
            for word in 0..16 {
                plaintext.extend_from_slice(&input.plaintext[word][block % 16].to_le_bytes());
                ciphertext.extend_from_slice(&input.ciphertext[word][block % 16].to_le_bytes());
            }
        }
        let nonce = std::array::from_fn(|byte| nonce[byte / 4].to_le_bytes()[byte % 4]);
        (
            ChaChaPublicInputs::new(&nonce, counter, &plaintext, &ciphertext),
            inputs,
        )
    }

    #[test]
    fn test_security_chacha_each_public_input_is_constrained() {
        let (public, inputs) = stream_fixture(17);
        for field in 0..4 {
            let mut fake = public.clone();
            match field {
                0 => fake.nonce[11] ^= 1,
                1 => fake.counter += 1,
                2 => *fake.plaintext.last_mut().unwrap() ^= 1,
                _ => *fake.ciphertext.last_mut().unwrap() ^= 1,
            }
            let proof = prove_stream_with_inputs::<Blake2sMerkleChannel>(
                5,
                PcsConfig::default(),
                &fake.nonce,
                fake.counter,
                &fake.plaintext,
                &fake.ciphertext,
                &inputs,
            );
            match proof {
                Ok(proof) => assert!(
                    verify_stream_with_public_inputs::<Blake2sMerkleChannel>(
                        proof,
                        &PcsConfig::default(),
                        &fake.nonce,
                        fake.counter,
                        &fake.plaintext,
                        &fake.ciphertext,
                    )
                    .is_err(),
                    "Forged field {field} was accepted"
                ),
                Err(error) => assert!(error.contains("ConstraintsNotSatisfied"), "{error}"),
            }
        }
    }

    #[test]
    fn test_security_chacha_prover_chosen_public_columns_rejected() {
        let (public, inputs) = stream_fixture(16);
        let config = PcsConfig::default();
        let twiddles = SimdBackend::precompute_twiddles(
            CanonicCoset::new(5 + config.fri_config.log_blowup_factor)
                .circle_domain()
                .half_coset,
        );
        let channel = &mut <Blake2sMerkleChannel as MerkleChannel>::C::default();
        let mut scheme =
            CommitmentSchemeProver::<SimdBackend, Blake2sMerkleChannel>::new(config, &twiddles);
        let mut builder = scheme.tree_builder();
        // A custom prover supplies columns for its own data, rather than the statement.
        builder.extend_evals(
            public_trace(
                4,
                64,
                &public.nonce,
                public.counter,
                &public.plaintext,
                &public.ciphertext,
            )
            .unwrap(),
        );
        builder.commit(channel);
        let fake_plaintext = vec![0x41; 16 * 64];
        let fake_ciphertext = vec![0x42; 16 * 64];
        let stmt = StreamStatement {
            log_size: 4,
            public_inputs: ChaChaPublicInputs::new(
                &[0xab; 12],
                99,
                &fake_plaintext,
                &fake_ciphertext,
            ),
        };
        stmt.mix_into(channel);
        let (trace, valid) = generate_stream_trace(4, &inputs);
        assert!(valid);
        let mut builder = scheme.tree_builder();
        builder.extend_evals(trace);
        builder.commit(channel);
        let component = ChaChaStreamComponent::new(
            &mut TraceLocationAllocator::new_with_preprocessed_columns(&public_column_ids(64)),
            ChaChaStreamEval {
                log_size: 4,
                claimed_sum: SecureField::zero(),
            },
            SecureField::zero(),
        );
        let stark_proof = prove(
            &[&component as &dyn ComponentProver<SimdBackend>],
            channel,
            scheme,
        )
        .unwrap();
        let proof = StreamProof { stmt, stark_proof };
        assert!(verify_stream_with_public_inputs::<Blake2sMerkleChannel>(
            proof.clone(),
            &config,
            &[0xab; 12],
            99,
            &fake_plaintext,
            &fake_ciphertext,
        )
        .is_err());
        assert!(verify_stream::<Blake2sMerkleChannel>(proof, &config).is_err());
    }

    #[test]
    fn test_stream_public_binding_with_padding_and_serialization() {
        for n_blocks in [1usize, 17, 33] {
            let (public, inputs) = stream_fixture(n_blocks);
            let log_size = n_blocks.next_power_of_two().ilog2().max(4);
            let proof = prove_stream_with_inputs::<Blake2sMerkleChannel>(
                log_size,
                PcsConfig::default(),
                &public.nonce,
                public.counter,
                &public.plaintext,
                &public.ciphertext,
                &inputs,
            )
            .unwrap();
            let bytes = bincode::serialize(&proof).unwrap();
            let proof = bincode::deserialize(&bytes).unwrap();
            verify_stream_with_public_inputs::<Blake2sMerkleChannel>(
                proof,
                &PcsConfig::default(),
                &public.nonce,
                public.counter,
                &public.plaintext,
                &public.ciphertext,
            )
            .unwrap();
        }
    }

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
            proof, &PcsConfig::default(), &nonce_bytes, 1, &fake_plaintext, &ciphertext_bytes
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
                proof.clone(), &PcsConfig::default(), &nonce_bytes, 1, &plaintext_bytes, &ciphertext_bytes
            ).is_ok(),
            "Verification with correct inputs should succeed"
        );

        // Verify with wrong plaintext should fail
        let wrong_plaintext = vec![0xffu8; plaintext_bytes.len()];
        assert!(
            verify_stream_with_public_inputs::<Blake2sMerkleChannel>(
                proof.clone(), &PcsConfig::default(), &nonce_bytes, 1, &wrong_plaintext, &ciphertext_bytes
            ).is_err(),
            "Verification with wrong plaintext should fail"
        );

        // Verify with wrong nonce should fail
        let wrong_nonce: [u8; 12] = [0xff; 12];
        assert!(
            verify_stream_with_public_inputs::<Blake2sMerkleChannel>(
                proof.clone(), &PcsConfig::default(), &wrong_nonce, 1, &plaintext_bytes, &ciphertext_bytes
            ).is_err(),
            "Verification with wrong nonce should fail"
        );

        // Verify with wrong counter should fail
        assert!(
            verify_stream_with_public_inputs::<Blake2sMerkleChannel>(
                proof.clone(), &PcsConfig::default(), &nonce_bytes, 999, &plaintext_bytes, &ciphertext_bytes
            ).is_err(),
            "Verification with wrong counter should fail"
        );

        // Verify with wrong ciphertext should fail
        let wrong_ciphertext = vec![0xffu8; ciphertext_bytes.len()];
        assert!(
            verify_stream_with_public_inputs::<Blake2sMerkleChannel>(
                proof, &PcsConfig::default(), &nonce_bytes, 1, &plaintext_bytes, &wrong_ciphertext
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
            verify_stream::<Blake2sMerkleChannel>(proof, &PcsConfig::default()).unwrap();
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
